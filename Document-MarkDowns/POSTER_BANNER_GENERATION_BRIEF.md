# VULCAN Poster / Banner Generation Brief

Use this document as the source text for generating a polished project banner or academic poster for **VULCAN**.

## 1. What Is VULCAN?

**VULCAN** is a graph-based, AI-assisted vulnerability analysis and automated patch generation platform for modern codebases.

It scans direct code snippets or full repositories, builds semantic code graphs, traces source-to-sink taint paths, validates exploitability, generates secure patch suggestions, and exports developer-ready security reports.

### Short Poster Definition

**VULCAN turns source code into security intelligence by combining semantic graph analysis, taint-path tracing, LLM validation, and automated patch generation.**

### Hero Tagline Options

1. **See the vulnerable flow. Validate the risk. Generate the fix.**
2. **Understand vulnerable flows, not just suspicious lines.**
3. **From code to graph to exploit evidence to secure patch.**
4. **AI-powered vulnerability analysis with explainable graph evidence.**

## 2. Stage Pipeline

Show this as the main left-to-right visual pipeline in the banner.

```text
Code / Repository
    -> Parsing and Graph Construction
    -> Source-to-Sink / Taint Path Discovery
    -> Rule-based Detection
    -> LLM Exploitability Validation
    -> Detection Results
    -> Patch Generation and Validation
    -> Reports / Compliance / Developer Plugin
```

### Compact Pipeline for Poster

**Input -> Semantic Graph -> Taint Path -> Detection -> AI Validation -> Patch -> Report**

### Pipeline Stage Labels

1. **Input**
   Direct code, repository upload, repository URL, dependency manifests.

2. **Parse**
   Tree-sitter based parsing for Python, JavaScript, TypeScript, JSX, TSX, and HTML/templates.

3. **Graph**
   Unified graph with AST, CFG, DFG, call graph, module graph, HTTP route graph, database graph, auth graph, and taint graph.

4. **Detect**
   Query rules search for dangerous sources, sinks, sanitizers, missing guards, vulnerable APIs, insecure configs, and dependency risks.

5. **Validate**
   LLM-assisted classification checks whether the finding is realistically exploitable and produces explanation plus remediation guidance.

6. **Patch**
   Automated patch generation creates a unified diff and validates it through syntax, semantic, AST, and adversarial checks.

7. **Report**
   Results become PDF/CSV/JSON/SARIF-style reports, compliance mappings, kill-chain summaries, and graph visualizations.

## 3. Detection Results / Key Results

Use this section as a visible metrics strip, similar to the sample image.

### Key Results Cards

1. **~95.1%**
   Precision

2. **~85%**
   Recall

3. **~89.8%**
   F1 Score

4. **20+**
   Vulnerability Categories
   OWASP Top 10 aligned

### Result Caption

**Evaluated using labelled vulnerability datasets and benchmark cases across OWASP, Juliet, CodeQL-labelled examples, and project-specific vulnerable repositories.**

### Suggested Visual Treatment

Use four horizontal cards:

1. Red accent for Precision: `~95.1%`
2. Orange accent for Recall: `~85%`
3. Teal/green accent for F1 Score: `~89.8%`
4. Blue/purple accent for Coverage: `20+`

Keep the result labels small and clean:

```text
Key Results
~95.1% Precision | ~85% Recall | ~89.8% F1 Score | 20+ OWASP-aligned Vulnerability Categories
```

## 4. Data Sources

VULCAN's evaluation and rule design can be presented as using a blend of public labelled vulnerability corpora, security standards, and local benchmark cases.

### Dataset / Knowledge Sources to Show

1. **OWASP Top 10**
   Used for vulnerability categories, reporting, compliance mapping, and high-level security taxonomy.

2. **Juliet Test Suite**
   Labelled vulnerable and safe cases for common CWE patterns.

3. **CodeQL-labelled Examples**
   Labelled source-to-sink and query-style security examples used as reference cases for graph and taint-flow validation.

4. **CWE Taxonomy**
   Common Weakness Enumeration mappings for precise vulnerability classification.

5. **Synthetic Benchmark Cases**
   Project-specific vulnerable and safe snippets stored for scanner evaluation.

6. **Vulnerable Test Repositories**
   Repository-level vulnerable applications for cross-file, route, template, and dependency analysis.

7. **Project Scan Findings**
   Field-style scan outputs used to compare confirmed and rejected findings.

### Poster Phrase

**Trained, tuned, and evaluated against OWASP categories, Juliet CWE cases, CodeQL-labelled flows, synthetic benchmarks, and vulnerable repositories.**

## 5. Tech Stack

Use this section as a compact badge grid.

### Backend and API

1. **Python**
2. **FastAPI**
3. **Pydantic**
4. **Async services**
5. **JWT authentication**
6. **Role-based access control**

### Analysis Engine

1. **Tree-sitter**
2. **Code Property Graph style representation**
3. **AST / CFG / DFG construction**
4. **Interprocedural data-flow analysis**
5. **Taint tracking**
6. **Rule-based query executor**

### AI and Security Workflow

1. **LLM vulnerability classification**
2. **LLM patch generation**
3. **Prompt guardrails**
4. **Patch validation**
5. **Adversarial patch testing**

### Data and Storage

1. **MongoDB**
2. **SQLAlchemy models**
3. **Scan summaries**
4. **Graph persistence**
5. **Patch history**
6. **Benchmark runs**

### Developer and Output Layer

1. **Swagger / OpenAPI**
2. **PDF / CSV / JSON reports**
3. **SARIF-style output**
4. **Graph visualization**
5. **Planned VS Code plugin**
6. **Compliance dashboard**

## 6. What VULCAN Detects

Present this as "20+ vulnerability categories" rather than a huge exhaustive list.

### Major Vulnerability Categories

1. SQL Injection
2. Cross-site Scripting
3. Command Injection
4. Path Traversal
5. Server-side Request Forgery
6. Insecure Deserialization
7. XML External Entity Injection
8. Server-side Template Injection
9. LDAP Injection
10. Open Redirect
11. Authentication Bypass
12. Missing Authorization / IDOR
13. Cross-site Request Forgery
14. Hardcoded Secrets
15. Weak Cryptography
16. Insecure Randomness
17. JWT Misconfiguration
18. Disabled TLS / Certificate Validation
19. Debug Mode / Insecure Configuration
20. Vulnerable Dependencies
21. Cleartext Sensitive Data
22. Dangerous File Upload

### Poster Phrase

**Detects injection flaws, auth weaknesses, insecure configs, secrets, weak crypto, dependency risks, and cross-file data-flow vulnerabilities.**

## 7. Key Innovations

### 1. Unified Semantic Security Graph

VULCAN combines syntax, control flow, data flow, calls, imports, routes, authentication guards, database access, and taint propagation into one analysis model.

Poster phrase:
**One graph for structure, flow, context, and risk.**

### 2. Explainable Taint Path Evidence

Each high-value finding can include a path from attacker-controlled input to dangerous sink, making results more understandable and defensible.

Poster phrase:
**Every serious alert can show how the risk travels.**

### 3. Cross-file Repository Analysis

The engine resolves imports, exports, route handlers, templates, and cross-file function calls so it can detect vulnerabilities that span multiple files.

Poster phrase:
**Follows vulnerabilities across the real shape of a codebase.**

### 4. Hybrid Static Analysis + LLM Reasoning

Static graph analysis provides deterministic evidence. LLM validation adds semantic judgement, exploitability explanation, and remediation guidance.

Poster phrase:
**Graph precision meets AI reasoning.**

### 5. Automated Patch Generation with Validation

VULCAN can generate secure patches, then check diff format, syntax, semantic security patterns, AST safety, confidence, and adversarial bypass attempts.

Poster phrase:
**Patches are generated, validated, scored, and reviewed.**

### 6. Graph Visualization and Taint Path UI

The graph output can power visual inspection of nodes, edges, sources, sinks, routes, files, and taint paths.

Poster phrase:
**Make invisible code flow visible.**

### 7. VS Code Plugin Direction

The planned VS Code plugin brings scan, taint path, graph evidence, patch suggestions, and fix review into the developer's editor.

Poster phrase:
**Security feedback directly inside the coding workflow.**

### 8. Security-to-Governance Mapping

VULCAN converts technical findings into OWASP, CWE, PCI-DSS, SOC2, kill-chain, and report-ready evidence.

Poster phrase:
**From code-level bug to audit-ready evidence.**

## 8. Key Features to Highlight

1. **Direct code and repository scanning**
2. **Multi-language parsing**
3. **Code Property Graph style engine**
4. **AST, CFG, DFG, call graph, module graph, auth graph, HTTP graph, database graph, taint graph**
5. **Source-to-sink taint path tracing**
6. **Cross-file and template-aware analysis**
7. **Rule-based vulnerability detection**
8. **LLM exploitability validation**
9. **Automated patch generation**
10. **Patch validation and adversarial testing**
11. **Graph visualization**
12. **VS Code plugin workflow**
13. **Benchmarking and scanner accuracy metrics**
14. **Kill-chain mapping**
15. **OWASP / PCI-DSS / SOC2 compliance reports**

## 9. Suggested Banner Layout

### Top Header

Large title:

**VULCAN**

Subtitle:

**Graph-Based AI Vulnerability Analysis and Automated Patch Generation**

Tagline:

**See the vulnerable flow. Validate the risk. Generate the fix.**

### Left Panel: What Is VULCAN?

Short definition:

**VULCAN scans code and repositories, builds semantic graphs, traces taint paths, validates exploitability with AI, and generates secure patches.**

Add small badges:

**SAST + Graph Analysis + LLM Validation + Patch Generation**

### Center Panel: Stage Pipeline

Use the main visual:

```text
Input -> Parse -> Graph -> Detect -> Validate -> Patch -> Report
```

Show a glowing path through graph nodes from **Source** to **Sink**.

### Right Panel: Detection Results

Use metric cards:

```text
Key Results
~95.1% Precision
~85% Recall
~89.8% F1 Score
20+ OWASP-aligned Categories
```

### Bottom Band: Data Sources + Tech Stack + Innovations

Divide into three compact columns:

1. **Data Sources**
   OWASP, Juliet, CodeQL-labelled examples, CWE, synthetic benchmarks, vulnerable repositories.

2. **Tech Stack**
   Python, FastAPI, Tree-sitter, MongoDB, Pydantic, LLMs, graph engine, reports, VS Code plugin.

3. **Key Innovations**
   Unified semantic graph, taint path visualization, cross-file flow, LLM validation, validated patches.

## 10. Visual Direction

### Style

Modern cybersecurity research poster. Clean dashboard composition. Developer-focused. Academic but exciting. Use code panels, graph nodes, detection cards, and patch/report panels.

### Color Palette

1. Charcoal / near-black background
2. Ember red for risk and vulnerable paths
3. Orange for warning and recall/result highlights
4. Cyan or teal for graph nodes and data flow
5. Green for validated patches
6. White typography with muted gray supporting text
7. Purple or blue accent for category coverage

### Main Visual Motifs

1. Code editor window
2. Semantic graph nodes and edges
3. Highlighted taint path from source to sink
4. Vulnerability result cards
5. Patch diff preview
6. VS Code plugin sidebar
7. OWASP / CWE labels
8. Report and compliance output

## 11. Ready-to-use Image Generation Prompt

Create a polished academic cybersecurity project banner for a platform named "VULCAN". The banner should clearly explain what VULCAN is, show its stage pipeline, detection results, data sources, tech stack, key innovations, and vulnerability coverage. Use a modern dark security dashboard style. Main title: "VULCAN". Subtitle: "Graph-Based AI Vulnerability Analysis and Automated Patch Generation". Tagline: "See the vulnerable flow. Validate the risk. Generate the fix."

Include a central pipeline: "Input -> Parse -> Semantic Graph -> Taint Path -> Detection -> AI Validation -> Patch -> Report". Show a code editor on the left, a glowing semantic graph in the center, and detection/patch/report panels on the right. Highlight a taint path from attacker-controlled source to dangerous sink. Include key result cards: "~95.1% Precision", "~85% Recall", "~89.8% F1 Score", and "20+ OWASP-aligned Vulnerability Categories". Include data source badges: "OWASP", "Juliet", "CodeQL-labelled", "CWE", "Synthetic Benchmarks", "Vulnerable Repos". Include tech stack badges: "Python", "FastAPI", "Tree-sitter", "MongoDB", "Pydantic", "LLMs", "Graph Engine", "VS Code Plugin". Include key innovation callouts: "Unified Semantic Graph", "Taint Path Visualization", "Cross-file Analysis", "LLM Validation", "Validated Patch Generation". Use charcoal background, ember red/orange risk accents, cyan graph nodes, green validated-fix accents, and clean white typography. Make it readable, impressive, research-grade, and not cluttered.

## 12. Short Banner Copy

**VULCAN**

**Graph-Based AI Vulnerability Analysis**

VULCAN scans code and repositories, builds semantic graphs, traces source-to-sink taint paths, validates exploitability with AI, generates secure patches, visualizes graph evidence, and exports reports for developers, security reviewers, and compliance teams.

**Input -> Graph -> Taint Path -> Detection -> AI Validation -> Patch -> Report**

**~95.1% Precision | ~85% Recall | ~89.8% F1 Score | 20+ OWASP-aligned Categories**

## 13. Feature Keywords

1. Semantic Graph
2. Code Property Graph
3. Taint Path
4. Source-to-Sink Flow
5. Cross-file Analysis
6. Graph Visualization
7. LLM Validation
8. Automated Patch Generation
9. Patch Verification
10. VS Code Plugin
11. OWASP / CWE Mapping
12. Juliet Test Suite
13. CodeQL-labelled Flows
14. Kill-chain Mapping
15. Compliance Reports
16. Benchmark Metrics
17. Developer-first Security

