# Vulcan Methodology Overview

This methodology describes how Vulcan performs end-to-end vulnerability analysis, from input ingestion and scanning through graph construction, query execution, LLM classification, patch generation, validation, benchmarking, kill-chain mapping, compliance mapping, and reporting.

## 1. Input and Scan Initiation

Vulcan accepts two main input modes.

1. Direct code input

   The user submits a code snippet, language, and optional filename. The backend creates a scan record with input type `DIRECT_CODE`, stores scan metadata in MongoDB, and starts an asynchronous scan worker. The code is analyzed as a single file.

2. Repository input

   The user submits either an uploaded local archive or a repository URL. The backend creates a scan record with input type `REPOSITORY`, extracts or clones the repository into a temporary workspace, optionally filters to selected file paths, and recursively collects supported source files.

Supported scanned source types include Python, JavaScript, TypeScript, JSX, TSX, and HTML/template files. Dependency manifests such as `requirements.txt`, `Pipfile`, `package.json`, and lockfiles are also included for dependency and vulnerable-component checks.

The scan lifecycle is tracked through status fields such as `PENDING`, `RUNNING`, `COMPLETED`, and `FAILED`, with progress, current file, logs, file counts, vulnerability summaries, and graph data persisted to MongoDB.


## 3. Semantic Graph Construction

Vulcan's vulnerability engine builds a Code Property Graph style semantic graph. The graph combines syntax, control, data, call, taint, module, HTTP, authentication, and database relationships.

### 3.1 Single-file Graph Construction

For direct code scans, the pipeline calls `SemanticGraphBuilder`.

The method is:

1. Select the parser language from the request.
2. Use the tree-sitter based `CPGParser` to parse the code.
3. Create AST/CPG nodes for modules, functions, methods, classes, calls, identifiers, parameters, assignments, returns, imports, literals, control statements, and expressions.
4. Add structural AST edges.
5. Run `InterproceduralDFG` over the CPG.
6. Add data-flow edges for variables, arguments, parameters, returns, interpolations, template literals, object properties, and attributes.
7. Add call-graph edges between caller and callee where resolution is possible.
8. Return a unified `SemanticGraph` that is compatible with the query engine and graph visualizer.

### 3.2 Repository Graph Construction

For repository scans, Vulcan uses `MultiFileRepositoryGraph`.

The method is:

1. Recursively discover supported files.
2. Split source files from HTML/template files.
3. Parse code files in parallel using a thread pool.
4. Build a per-file CPG for every supported file.
5. Enrich each per-file CPG with interprocedural DFG edges.
6. Namespace node IDs by file hash so same-named functions in different files do not collide.
7. Extract exports, imports, re-exports, module definitions, and imported symbols.
8. Build a global symbol table for all modules.
9. Resolve import/export relationships.
10. Create cross-file edges such as import-call, export-return, module-reference, and file-contains relationships.
11. Propagate DFG edges across import/export links so taint can move across files.
12. Build a repository-wide name-based call graph.
13. Propagate taint through cross-file function arguments and returns.
14. Link route decorators, HTTP routes, handlers, middleware, and auth guards.
15. Parse HTML/templates and link frontend/template flows to backend handlers where possible.
16. Return one global CPG plus statistics such as total modules, nodes, edges, imports, exports, and cross-file edges.

## 4. Graph Types and Edge Families

Vulcan stores one unified graph, but the graph contains multiple logical graph types.

1. AST graph

   Represents parent-child syntax structure using `AST_CHILD` edges.

2. Control-flow graph

   Represents execution order and branches using `CONTROL_FLOW`, `CFG_NEXT`, `CFG_BRANCH_TRUE`, `CFG_BRANCH_FALSE`, `CFG_LOOP_ENTRY`, `CFG_LOOP_EXIT`, and `CFG_EXCEPTION`.

3. Data-flow graph

   Represents value movement using `DATA_FLOW`, `DFG_FLOW`, `DFG_INTERP`, `DFG_TEMPLATE`, `DFG_PARAM_PASS`, `DFG_RET`, `DFG_PROPERTY`, and `DFG_ATTR`.

4. Call graph

   Represents function and method invocation using `CALL_GRAPH`, `CALL_ARG`, and `CALL_RETURN`.

5. Module graph

   Represents repository structure and imports using `IMPORTS`, `DEFINES`, and `USES`, plus cross-file import/export relationships from the multi-file linker.

6. Taint graph

   Represents security-relevant source-to-sink propagation using `TAINT_SOURCE`, `TAINT_FLOW`, `TAINT_SINK`, and `SANITIZED`.

7. Auth and permission graph

   Represents access-control coverage using `AUTH_COVERAGE` and `PERMISSION_FLOW`.

8. HTTP/API graph

   Represents web routes and request flow using `HTTP_FLOW`, `HTTP_ROUTE`, and `HTTP_MIDDLEWARE`.

9. Database graph

   Represents ORM, SQL, and parameter links using `ORM_FLOW` and `SQL_PARAM`.

These edge families allow Vulcan to analyze not only local syntax patterns, but also how user input travels across functions, modules, HTTP handlers, templates, and dangerous sinks.

## 5. Query Execution and Candidate Slice Extraction

After graph construction, Vulcan executes two complementary detection stages.

### 5.1 Broad Path Discovery

`PathDiscovery` performs a broad source-to-sink traversal over security-relevant graph edges. It collects potential sources, sinks, and sanitizers from the query store and graph metadata. Then it runs bounded BFS from every source toward known sinks.

The traversal uses edge types that can carry data or security meaning, including DFG, taint, call-graph, auth, and HTTP route edges. Candidate paths are scored using heuristics such as path length, source-to-sink proximity, sanitizer presence, boundary crossings, auth coverage, and ambiguity. Only candidates above a configured threshold become `CodeSlice` objects.

### 5.2 Rule-based Query Execution

The query store loads static rules from `queries/queries.json`. Each rule defines items such as:

1. Rule ID and name.
2. OWASP category.
3. CWE.
4. Severity and confidence.
5. Source patterns.
6. Sink patterns.
7. Sanitizer patterns.
8. Required guards.
9. Graph patterns such as `DFG_FLOW` or `TAINT_FLOW`.
10. Regex patterns for configuration, dependency, and dangerous API checks.

`QueryExecutor` resolves matching source nodes and sink nodes, searches paths between them, applies guard-aware logic, extracts minimal code snippets, and creates `CodeSlice` evidence objects. Regex-based rules scan raw file contents and manifest files directly when graph traversal is unnecessary.

Each code slice contains the rule, source, sink, data-flow path, file location, snippet, pattern type, and a human-readable reason.

## 6. LLM Vulnerability Classification

Static detection can over-report because not every suspicious pattern is exploitable. Vulcan therefore sends candidate slices to an LLM validation layer.

The classifier:

1. Sorts candidate slices by severity and confidence.
2. Skips LLM calls for presence-based findings where detection alone is sufficient, such as hardcoded secrets, weak crypto, debug mode, disabled certificate validation, insecure deserialization, and vulnerable component rules.
3. Uses a configurable LLM call budget.
4. Runs multiple classifier workers in parallel.
5. Gives each worker its own role-aware LLM pool.
6. Falls back to static classification if the pool is exhausted, disabled, rate-limited, or returns invalid output.

The LLM prompt includes the code slice, language guess, source, sink, rule description, OWASP category, and CWE. The model is instructed to return structured JSON containing whether the code is vulnerable, vulnerability type, severity, explanation, and recommendation.

The response parser supports both the current Vulcan format and older classification formats. Final vulnerability decisions combine static severity/confidence with LLM classification, exploitability, confidence, and remediation. Safe slices are filtered out. Vulnerable and likely vulnerable results are formatted into scan findings.

## 7. Vulnerability Result Formatting

Confirmed findings are deduplicated and normalized before storage.

For direct code scans, duplicate findings are collapsed by type, file, sink line, sink, and evidence quality. For repository scans, file paths are normalized to repo-relative paths. DFG findings are preferred when they provide stronger evidence, longer source-to-sink paths, and higher confidence.

Each stored finding includes:

1. Vulnerability ID.
2. Type.
3. Severity.
4. Confidence.
5. CWE and OWASP mapping.
6. Location.
7. Code snippet.
8. Source and sink.
9. Pattern type.
10. Data-flow path evidence.
11. LLM explanation and remediation.
12. Optional exploit/Payload-of-Concept enrichment for high and critical findings.

## 8. Patch Generation Methodology

Patch generation is handled by the patch module after a vulnerability has been found. It uses the stored vulnerability context rather than scanning the whole repository again.

The patch context contains:

1. Vulnerability ID.
2. File path.
3. Language.
4. Vulnerability type.
5. CWE and OWASP category.
6. Vulnerable slice.
7. Surrounding context.
8. Source.
9. Sink.
10. Taint path.

Before any LLM call, guardrails are applied:

1. Rate limiting prevents abuse.
2. Slice length limits prevent oversized prompts.
3. Secret detection rejects prompts containing sensitive values.

### 8.1 Industrial CoT Patch Methodology

Vulcan uses a structured two-call, chain-of-thought inspired remediation workflow.

The first call builds an industrial four-phase security reasoning prompt. The phases are:

1. Threat modeling

   The model identifies attacker-controlled inputs, maps them to the sink, constructs a concrete exploit, describes attacker impact, and estimates CVSS-style risk.

2. Fix design

   The model identifies the root cause, selects the secure API or coding pattern, lists the exact lines to remove and add, records any required imports, and estimates breakage risk.

3. Adversarial self-verification

   The model switches into attacker mode and tries to bypass its own proposed fix using encoding bypasses, type coercion, null or boundary inputs, second-order attacks, and race/TOCTOU scenarios. If a bypass is found, the fix must be strengthened.

4. Formal patch specification

   The model ends with a machine-readable `PATCH_SPEC_BEGIN` to `PATCH_SPEC_END` block containing file, language, vulnerability type, changed lines, new imports, breakage risk, and bypass verdict.

The second call turns that formal patch specification into a unified diff. The required output is a valid unified diff only, with no prose or markdown.

### 8.2 Retry and Self-critique

Patch generation uses up to three attempts. Attempt 0 uses the industrial CoT prompt. Attempts 1 and 2 use critique prompts that include the failed patch and validation failures. Vulcan keeps the best attempt by confidence rather than blindly accepting the last output.

The loop stops early when the confidence reaches the target threshold. If all validations pass but confidence is still below the goal, the loop can stop because there is no concrete validation failure to critique.

## 9. Patch Validation Methodology

Patch validation is a multi-stage gate.

1. Diff format validation

   Vulcan parses the unified diff, confirms it has a target file, and checks that the target file matches the vulnerable file.

2. Syntax validation

   Python patches are checked with `ast.parse`. Indented snippets are dedented or wrapped in a dummy function when needed. JavaScript and TypeScript patches are checked with `esprima` when available. If the language is unknown, syntax validation is skipped with an explicit result.

3. Diff application validation

   Vulcan attempts to apply the diff to the original context. If the stored slice is shorter than the full-file hunk, this can be treated as a soft success and the patched view is reconstructed from added and context lines.

4. Semantic validation

   Vulnerability-specific validators check whether the expected secure pattern appears and whether the dangerous pattern was removed. Examples include parameterized SQL queries for SQL injection, escaping or safe rendering for XSS, `shell=False` or argument arrays for command injection, safe XML parsing for XXE, ownership checks for IDOR, allowlists for redirects, secure randomness for tokens, and certificate validation for TLS.

5. Python AST-level validation

   Python patches receive additional AST checks to catch problems that simple string checks miss.

6. Confidence scoring

   The orchestrator computes confidence from validation outcomes and creates a score breakdown.

7. Adversarial attack simulation

   A separate LLM call acts as a penetration tester against the generated patch. It tests direct payloads, encoding bypasses, type coercion, boundary cases, and second-order attacks. This result is non-blocking, but it is stored with the patch as extra assurance.

8. Persistence and review

   The patch, validations, confidence, attack test, version, explanation, and review status are stored in MongoDB. Patch status is synced back into the scan summary so reports and UI screens can show patch readiness per vulnerability.

Patch statuses include generated, rejected, validated, pending review, and applied-pending depending on the workflow stage.

## 10. Benchmarking Methodology

Benchmarking measures scanner behavior against known labeled cases and field-confirmed findings.

### 10.1 Synthetic Benchmark

The synthetic benchmark loads stored test cases from MongoDB. Each case has code, language, CWE, vulnerability type, and label such as vulnerable or safe. The benchmark runs the semantic pipeline on each case, optionally with LLM enabled.

For every case, Vulcan records:

1. Whether a vulnerability was detected.
2. Detected type.
3. Confidence.
4. Outcome: true positive, false positive, false negative, or true negative.

It then computes precision, recall, F1 score, false-positive rate, duration, total cases, and per-CWE metrics.

### 10.2 Field Benchmark

The field benchmark uses real scan findings that were later judged by an AI oracle as confirmed or rejected. Confirmed findings are counted as true positives. Rejected findings are counted as false positives.

Because field benchmarking only sees findings already produced by the scanner, it can measure field precision but cannot honestly measure recall. The implementation keeps this limitation explicit.

## 11. Kill-chain Mapping Methodology

After a scan completes, Vulcan maps vulnerabilities to MITRE ATT&CK-style kill-chain stages.

The stages are:

1. Reconnaissance.
2. Initial Access.
3. Execution.
4. Persistence.
5. Privilege Escalation.
6. Credential Access.
7. Exfiltration.
8. Impact.

Mapping is keyword-based. For example, SQL injection, SSRF, authentication bypass, LDAP injection, and XXE map to Initial Access. Command injection, code injection, SSTI, unsafe eval, and insecure deserialization map to Execution. Hardcoded secrets, weak crypto, JWT issues, and cleartext storage map to Credential Access. XSS and CSRF map to Exfiltration.

The kill-chain endpoint groups vulnerabilities by stage, calculates stage risk, creates edges between active stages, computes a blast-radius score from stage breadth, severity, and execution/impact presence, and matches active stages against attack-chain templates such as full application takeover, injection-to-data-breach, credential theft, and web shell deployment.

The result includes a narrative that explains how an attacker could chain the discovered weaknesses.

## 12. Compliance Mapping Methodology

Compliance mapping converts vulnerability findings into governance-oriented control results.

Supported frameworks include:

1. OWASP Top 10 2021.
2. PCI-DSS 4.0.
3. SOC2 Trust Service Criteria.

The method is:

1. Extract the OWASP category from each vulnerability.
2. Map the OWASP category to PCI-DSS and SOC2 controls using fixed mapping dictionaries.
3. Attach finding summaries to each relevant control.
4. Mark controls as `PASS`, `WARN`, or `FAIL`.
5. Mark high and critical findings as failures for affected controls.
6. Compute a compliance score where pass contributes fully and warning contributes partially.
7. Return structured compliance data or generate a branded PDF report.

This allows technical scan output to become audit-facing evidence.

## 13. Reporting Methodology

Reports are generated from completed scan summaries.

The report service:

1. Lists completed scans visible to the current user.
2. Retrieves a specific scan summary.
3. Merges patch status into each vulnerability.
4. Exports reports as PDF, CSV, or JSON depending on the endpoint.
5. Includes scan metadata, input type, file counts, duration, severity summary, vulnerability details, evidence, recommendations, and patch validation summaries.

PDF export uses ReportLab when installed. Reports are access-controlled so normal users see their own completed scans while admins can access all completed scan reports.

## 14. End-to-end Pipeline Summary

The complete method is:

1. User submits direct code or repository input.
2. Scan record is created and an async worker starts.
3. Repository input is extracted or cloned and supported files are collected.
4. Source files are parsed into CPG/semantic graph nodes.
5. AST, CFG, DFG, call, taint, module, auth, HTTP, and database edges are created.
6. Repository scans resolve imports, exports, re-exports, cross-file calls, route handlers, auth guards, HTML/template links, and cross-file data flow.
7. Broad path discovery finds high-signal source-to-sink candidates.
8. Static query rules execute graph and regex checks.
9. Candidate slices are deduplicated and sent to the classifier.
10. LLM classification validates exploitability and filters false positives.
11. Confirmed vulnerabilities are formatted, normalized, deduplicated, enriched, and stored.
12. Scan summary, graph data, logs, and severity counts are persisted.
13. Optional confirmation/oracle tasks run asynchronously.
14. Patch generation can be launched for a stored vulnerability.
15. Patch generation uses guarded prompts, industrial CoT analysis, unified diff generation, critique retries, validation, scoring, and adversarial attack simulation.
16. Benchmarks evaluate synthetic and field performance.
17. Kill-chain mapping translates findings into attacker progression.
18. Compliance mapping translates findings into OWASP, PCI-DSS, and SOC2 controls.
19. Reports export the final technical and governance evidence.

