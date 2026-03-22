# VULCAN SRS Enhancement (30% -> 60%)

This document contains:
1. Algorithm comparison against `verify.md` and newly identified algorithms used in the project.
2. Updated SRS sections for **60% implementation**, especially Deployment and Testing/Evaluation.

---

## A) Algorithm Delta vs `verify.md`

### Algorithms already listed in `verify.md`
- AST Parsing Algorithm
- Data Flow Graph Construction
- Taint Tracking and Path Extraction
- LLM-Based Vulnerability Classification

### New algorithms implemented in project but not explicitly listed as named algorithms in `verify.md`

| New Algorithm | Why it is new vs `verify.md` | Implementation Location | Core Purpose |
|---|---|---|---|
| Heuristic Path Discovery and Scoring | `verify.md` mentions path traversal, but not the separate candidate ranking/scoring algorithm | `semantic_engine/path_discovery.py` | Finds and ranks likely vulnerable source->sink paths using IIS/proximity/boundary/auth-gap/sanitizer signals |
| Cross-File Import/Export Resolution and DFG Propagation | `verify.md` mentions multi-file analysis conceptually, but not this explicit resolution/propagation algorithm | `app/domain/analysis/multi_file_repo_graph.py` | Resolves module links and creates cross-file semantic/data-flow edges |
| Vulnerability Deduplication and Ranking Algorithm | Not documented as a distinct algorithm in `verify.md` | `semantic_engine/query_executor/executor.py`, `semantic_engine/pipeline.py`, `app/services/scan_service.py` | Collapses duplicate findings and keeps strongest evidence by severity/confidence/pattern quality |
| Multi-Provider LLM Retry/Fallback Scheduling Algorithm | `verify.md` lists classification, but not provider-orchestration strategy | `semantic_engine/classifier/llm_service.py` | Handles timeout, rate-limit backoff, provider fallback order, and cached prompt responses |

### 4.1.2.1 Algorithm: Heuristic Path Discovery and Candidate Ranking
**Input:** Unified semantic graph + source map + query store  
**Output:** Ranked vulnerability candidate slices

**Pseudocode**
1. `procedure DiscoverCandidates(Graph, SourceCodeMap, Rules)`
2. `Collect all source patterns, sink patterns, sanitizer patterns from Rules`
3. `Resolve source nodes and sink nodes in Graph`
4. `Build adjacency for DFG/TAINT/CALL/HTTP/AUTH edges`
5. `for each Source:`
6. `  BFS paths to reachable sinks (depth + candidate limits)`
7. `  Score each path using:`
8. `    IIS + danger proximity + boundary crossings + sanitizer ambiguity + auth gap`
9. `  keep paths above threshold`
10. `Extract snippets + locations for top-K candidates`
11. `return RankedCodeSlices`
12. `end procedure`

### 4.1.2.2 Algorithm: Cross-File Symbol Resolution and Data-Flow Propagation
**Input:** Repository files + per-file CPGs  
**Output:** Global CPG with cross-file semantic and DFG edges

**Pseudocode**
1. `procedure BuildGlobalRepoGraph(Repo)`
2. `Scan source files and parse each into file-level CPG`
3. `Extract imports/exports for each module`
4. `Build global symbol table`
5. `Resolve import -> export matches (with cache and path normalization)`
6. `Create cross-file edges (IMPORT_CALL, EXPORT_RET, MODULE_REF)`
7. `Propagate DFG_FLOW via import/export identity mappings`
8. `Link repo-wide call graph by name resolution`
9. `return GlobalCPG`
10. `end procedure`

### 4.1.2.3 Algorithm: Vulnerability Deduplication and Prioritized Selection
**Input:** Raw findings from discovery/query/classification  
**Output:** Unique ranked vulnerability set

**Pseudocode**
1. `procedure DedupeFindings(Findings)`
2. `Group by key(rule, sink, file, start_line, end_line [, source])`
3. `For each group, compute ranking tuple using:`
4. `  severity rank, confidence, has_snippet, path_type_strength, path_length`
5. `Keep highest-ranked item per group`
6. `Sort retained findings by severity then confidence`
7. `return DedupedFindings`
8. `end procedure`

### 4.1.2.4 Algorithm: LLM Provider Fallback with Retry and Rate-Limit Control
**Input:** Prompt + provider configuration  
**Output:** Parsed classification result or static fallback

**Pseudocode**
1. `procedure ClassifyWithFallback(Prompt, Providers)`
2. `Try primary provider with min-interval + semaphore`
3. `On 429/timeout/transient error, exponential backoff retry`
4. `If failed, iterate fallback providers in priority order`
5. `Parse first successful JSON response`
6. `If all providers fail, return pattern-based fallback result`
7. `Cache result by prompt hash`
8. `return ClassificationResult`
9. `end procedure`

---

## B) Updated SRS for 60% Implementation

## 4.6 Deployment (Updated for 60%)

At 60% implementation, deployment is no longer limited to a partially integrated local prototype. The backend now supports stable local deployment, VPS deployment, and containerized multi-service deployment with repository scanning and graph generation operational.

### 4.6.1 Deployment Environment Overview (60%)
The VULCAN system is currently deployable with the following setup:

- Backend Deployment
1. Framework: FastAPI 0.110+ (Python 3.10+)
2. Application Server: Uvicorn (ASGI)
3. Runtime: Local machine / VPS / VM
4. Persistence: MongoDB (primary runtime store), SQLAlchemy relational models available
5. Analysis Stack: tree-sitter grammars + semantic engine + query rules
6. LLM Providers: OpenAI / GitHub Models / Anthropic / Groq with fallback support
7. Package Management: `pip` + `venv`

- Frontend Deployment (integration-ready)
1. Framework: React (separate repo)
2. Runtime: Node.js
3. Backend access via `/api/v1/*`
4. Supports scan start/status/summary/logs + reports/patches integration

- Containerization (now practical at 60%)
1. `Dockerfile` for backend present
2. `docker-compose.yml` present for service orchestration
3. Deployment supports combined service bring-up for demo/staging

### 4.6.2 Backend Deployment Configuration (60%)
Backend deployment now supports:

- Local Deployment Steps
1. Create Python virtual environment
2. Install dependencies (`requirements.txt`)
3. Configure `.env` (Mongo/JWT/LLM/provider settings)
4. Run `uvicorn app.main:app --reload`
5. Verify `/health` and `/docs`

- VPS/VM Deployment Steps
1. Provision Python runtime and MongoDB
2. Set production `.env` variables (JWT secret, DB URI, CORS, API keys)
3. Launch via process manager (systemd/supervisor) or container
4. Expose API with reverse proxy (Nginx/Caddy)
5. Validate scan endpoints and background task behavior

### 4.6.3 Container Deployment Increment (New at 60%)
Compared to the 30% phase, 60% deployment includes:
1. Repository scan flow and semantic graph build within deployment runtime
2. Operational query engine (`queries.json`) in deployed environment
3. LLM fallback behavior active in runtime when provider fails
4. Docker-ready backend flow validated for scan APIs

### 4.6.4 Deployment Readiness Status
Current status at 60%:
1. Local and VPS backend deployment: **Ready**
2. End-to-end scan/report API operation: **Ready**
3. Containerized backend deployment: **Ready (staging/demo level)**
4. Full production hardening (HA scaling, observability, autoscaling): **Planned for later phase**

---

# 5 Chapter 5: Testing and Evaluation (60% Increment Update)

At 60% implementation, testing extends beyond 30% baseline authentication + direct scan checks and now includes cross-file graphing, repository-level analysis, query/path discovery behavior, deduplication logic, and patch-module validation.

## 5.1 Unit Testing (New Incremental Tests)

### Unit Testing 1: Cross-File Flow Resolution
Testing Objective: Verify that import/export links produce cross-file flow paths.

| No. | Test Case / Script | Input | Expected Result | Actual Result |
|---|---|---|---|---|
| 1 | `tests/test_cross_file_flow.py` | multi-file repo fixture | import->export resolution succeeds | Pass |
| 2 | `tests/test_import_export_patterns.py` | ES module patterns | symbols resolved correctly | Pass |
| 3 | `tests/test_reexport_chain.py` | chained re-exports | final symbol trace preserved | Pass |

Table 5.1: Cross-File Flow Unit Tests

### Unit Testing 2: JS/TS Export Variants
Testing Objective: Validate CommonJS and TypeScript export patterns.

| No. | Test Case / Script | Input | Expected Result | Actual Result |
|---|---|---|---|---|
| 1 | `tests/test_commonjs_exports.py` | `module.exports` usage | export captured | Pass |
| 2 | `tests/test_ts_export_equals.py` | `export =` syntax | export captured | Pass |
| 3 | `tests/test_js_flows.py` | JS data flow snippets | flow edges generated | Pass |

Table 5.2: JS/TS Export Unit Tests

### Unit Testing 3: Patch Module Validators
Testing Objective: Ensure patch validation components behave correctly.

| No. | Test Case / Script | Component | Expected Result | Actual Result |
|---|---|---|---|---|
| 1 | `tests/patch_module/test_syntax_validator.py` | syntax validator | invalid patches rejected | Pass |
| 2 | `tests/patch_module/test_semantic_validator.py` | semantic validator | semantic regressions detected | Pass |
| 3 | `tests/patch_module/test_orchestrator.py` | patch orchestration | flow executes with guard checks | Pass |

Table 5.3: Patch Module Unit Tests

## 5.2 Functional Testing (60% Features)

### Functional Testing 1: Repository Scan Workflow
Objective: Verify repository-level scan with status polling and summary retrieval.

| No. | Test Case | Endpoint Flow | Expected Result | Actual Result | Result |
|---|---|---|---|---|---|
| 1 | Start repository scan | `POST /scans/start` with `repo_id` | scan_id returned, state PENDING/RUNNING | successful | Pass |
| 2 | Poll status | `GET /scans/{scan_id}/status` | progress and file counters update | successful | Pass |
| 3 | Fetch summary | `GET /scans/{scan_id}/summary` | vulnerability summary returned | successful | Pass |

Table 5.4: Repository Scan Functional Tests

### Functional Testing 2: Graph Retrieval
Objective: Validate graph payload access after scan completion.

| No. | Test Case | Endpoint | Expected Result | Actual Result | Result |
|---|---|---|---|---|---|
| 1 | Fetch file graph | `GET /graphs/{scan_id}/file/{file_id}` | node/edge graph returned | successful | Pass |
| 2 | Fetch node details | `GET /graphs/{scan_id}/nodes/{node_id}` | node metadata returned | successful | Pass |

Table 5.5: Graph Endpoint Functional Tests

### Functional Testing 3: Patch Workflow
Objective: Validate patch generate -> validate -> apply/export chain.

| No. | Test Case | Endpoint Flow | Expected Result | Actual Result | Result |
|---|---|---|---|---|---|
| 1 | Generate patch | `POST /patches/generate` | patch id and metadata returned | successful | Pass |
| 2 | Validate patch | `POST /patches/{id}/validate` | validation summary returned | successful | Pass |
| 3 | Apply/export patch | `POST /patches/{id}/apply`, `GET /patches/{id}/export` | patched output available | successful | Pass |

Table 5.6: Patch Functional Tests

## 5.3 Business Rules Testing (Updated)

The 60% phase adds rule behavior validation for deduplication, sanitizer impact, and confidence fusion.

### Business Rule Tested 1: Sanitizer-Aware Confidence Adjustment
Condition: Taint path includes sanitizer indicators  
Action: Lower confidence and possibly reduce effective severity

| Condition | Sanitizer Found? | Base Severity | Action |
|---|---|---|---|
| C1 | No | Critical/High | Keep severity and confidence |
| C2 | Yes (heuristic) | Critical/High | Reduce confidence |
| C3 | Yes (explicit) | Any | downgrade risk interpretation |

Table 5.7: Sanitizer-Aware Rule Testing

### Business Rule Tested 2: Duplicate Finding Collapsing
Condition: Multiple findings same rule+location+sink  
Action: Keep highest-ranked evidence record only

| Condition | Duplicate Key Match | Ranking Compared | Action |
|---|---|---|---|
| C1 | Yes | new > existing | replace existing |
| C2 | Yes | new <= existing | keep existing |
| C3 | No | N/A | insert new finding |

Table 5.8: Deduplication Rule Testing

## 5.4 Integration Testing (60% Increment)

### Integration Testing 1: End-to-End Repository Scan Integration
Testing Objective: Verify API -> scan service -> semantic pipeline -> summary storage integration.

| No. | Test Case | Modules Involved | Expected Result | Actual Result | Result |
|---|---|---|---|---|---|
| 1 | Repository scan start to completion | `scans.py -> ScanService -> SemanticPipeline -> MongoDB` | summary persisted and retrievable | successful | Pass |
| 2 | Scan logs and progress visibility | `ScanService -> /scans/{id}/logs/status` | runtime logs visible | successful | Pass |

Table 5.9: Repository Pipeline Integration

### Integration Testing 2: Multi-File Graph + Query + Classification
Testing Objective: Verify cross-file graph edges are consumable by query executor and classifier.

| No. | Test Case | Modules | Expected Result | Actual Result | Result |
|---|---|---|---|---|---|
| 1 | Cross-file vulnerable flow | `MultiFileRepositoryGraph -> QueryExecutor -> SliceClassifier` | vulnerability surfaced with location/evidence | successful | Pass |
| 2 | LLM unavailable fallback | `SliceClassifier -> LLMService fallback` | static fallback classification returned | successful | Pass |

Table 5.10: Cross-File + Classification Integration

### Integration Testing 3: Patch Attachment in Scan Summary
Testing Objective: Validate that generated patches are linked back in scan summary response.

| No. | Test Case | Modules | Expected Result | Actual Result | Result |
|---|---|---|---|---|---|
| 1 | Summary with patch status | `PatchRepository -> ScanService.summary` | patch status/confidence shown per vulnerability | successful | Pass |

Table 5.11: Patch-Summary Integration

## 5.5 Summary of Testing (60% Status)

Based on 60% phase testing:
1. Unit tests now cover cross-file resolution, JS/TS export patterns, and patch validation modules.
2. Functional tests now include repository scan lifecycle, graph retrieval, and patch workflows.
3. Business-rule testing now covers sanitizer-aware scoring and deduplication behavior.
4. Integration testing confirms repository scan -> graph/query -> classification -> summary/patch data flow.

Overall, the system has progressed from a 30% direct-scan-focused implementation to a **60% integrated semantic analysis platform** with stable repository-level scanning and richer operational workflows.

---

# 6 Chapter 6: Conclusion and Future Work

This chapter concludes the VULCAN project at its current implementation stage and outlines practical future enhancements.

## 6.1 Conclusion

The core goal of VULCAN is to provide an intelligent vulnerability analysis platform that combines static semantic analysis with LLM-assisted validation for modern codebases. At the current 60% completion stage, that goal has been substantially addressed through a working backend that supports direct-code and repository-level scanning, graph-based analysis, vulnerability reporting, and patch workflows.

### Project Goal Achievement
1. A modular FastAPI backend has been established with production-oriented route organization.
2. Semantic analysis pipeline is implemented with CPG generation, interprocedural DFG, query-driven taint/path detection, and LLM classification fallback.
3. Repository scanning and cross-file flow support are operational, moving beyond single-file prototypes.
4. Reporting, graph retrieval, and patch-generation/validation flows are integrated into API workflows.

### Problem-Solution Reflection
The original problem involved detecting real vulnerabilities (not only pattern matches) across complex code paths. VULCAN addresses this by:
1. Building structural code graphs rather than relying only on regex signatures.
2. Tracking source-to-sink propagation with multi-edge path analysis.
3. Reducing false positives through classification and confidence/severity fusion.
4. Supporting multi-file repositories where vulnerabilities often span modules.

### Major Implemented Functionalities
1. Auth and access control (JWT, role-aware routes, OAuth support).
2. Direct and repository scan lifecycle (`start`, `status`, `logs`, `summary`, `cancel`).
3. Query-rule execution with sanitizer/guard-aware behavior.
4. Graph endpoints for node/edge-level investigation.
5. Patch module for generation, validation, application, and export.
6. Multi-provider LLM integration with retry and fallback.

### Current Limitations
1. Hybrid persistence is functional but not yet unified into a single mature data strategy.
2. Full benchmark-backed accuracy/recall evaluation is not yet finalized.
3. Some advanced security checks still rely on heuristic/rule confidence rather than deep semantic theorem-level verification.
4. Production hardening (full observability, HA deployment, autoscaling, SLO-based operations) is still in progress.

### User and Administrator Value
1. Developers receive actionable findings with location, evidence path, and remediation context.
2. Security reviewers benefit from graph-backed explainability over opaque scanner outputs.
3. Administrators get controllable scan workflows, summaries, and report/patch visibility for governance.

## 6.2 Future Work

The next phase should focus on improving precision, scalability, and operational readiness.

### Planned but Not Fully Implemented Yet
1. End-to-end production-grade CI/CD deployment with environment promotion gates.
2. Rich frontend analytics and collaborative triage workflows.
3. Comprehensive historical trend dashboards and risk posture tracking.

### Technical Enhancements
1. Rule quality improvements using rule tuning pipelines and false-positive feedback loops.
2. Expanded interprocedural/context-sensitive flow analysis for framework-specific sinks/sanitizers.
3. Pluggable policy engine for organization-specific compliance checks.
4. Deeper patch-quality scoring with automated semantic regression checks.

### AI/ML and Automation Opportunities
1. Learning-assisted ranking model trained on validated findings to prioritize true positives.
2. Automated remediation suggestion refinement based on accepted/rejected patches.
3. Predictive risk forecasting by repository, team, and component change patterns.
4. Agent-assisted secure code review summaries for pull requests.

### UI/UX and Product Improvements
1. Interactive graph exploration with path pinning and evidence-step playback.
2. Better finding triage workflow (assign, acknowledge, suppress, reopen) with audit trail.
3. Guided remediation views (before/after diff + validation outcomes).

### Scalability and Deployment Strategy
1. Cloud-native deployment with horizontal workers for concurrent repository scans.
2. Queue-based scan orchestration and backpressure control for large teams.
3. Multi-tenant isolation and branch/environment-aware scanning policies.
4. Observability stack integration (metrics, tracing, structured logs, alerting).

### External Integrations
1. DevOps integrations (GitHub/GitLab/Bitbucket PR checks).
2. Ticketing/security workflows (Jira, ServiceNow, SIEM pipelines).
3. Optional enterprise integrations for compliance reporting and governance platforms.

### Long-Term Alignment
Future versions of VULCAN should align with evolving secure development practices, AI-assisted engineering workflows, and emerging vulnerability classes in modern polyglot and cloud-native architectures.
