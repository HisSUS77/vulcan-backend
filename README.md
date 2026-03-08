# VULCAN Backend: Verified Implementation Documentation

This README is a code-verified implementation document aligned with your SRS section format.
It corrects any mismatch between the previous draft and current codebase implementation.

## 4.1.1 Step-by-Step Implementation Methodology

### 4.1.1.1 Backend Architecture Setup
- FastAPI is the primary backend framework (`app/main.py`, `app/api/api_v1.py`).
- Project is modularized across:
  - `app/models/` (SQLAlchemy models)
  - `app/services/` (auth, scan, report, repository, patch, notification services)
  - `app/domain/analysis/` (CPG parser, interprocedural DFG, taint, slicing, multi-file graph)
  - `semantic_engine/` (query store, query executor, path discovery, LLM classifier pipeline)
- Configuration, auth, and DB layers are implemented in:
  - `app/core/config.py`, `app/core/security.py`
  - `app/api/deps.py`, `app/core/permissions.py`
  - `app/db/*`

### 4.1.1.2 Static Code Parsing Implementation
Implemented and used:
- `CPGParser` (tree-sitter based AST/CPG extraction for Python/JS/TS)
- `InterproceduralDFG` (intra + interprocedural data flow)
- `SemanticGraphBuilder` (CPG + DFG orchestration)

Implemented but not primary production path:
- `CFGBuilder`/`DFGBuilder` in `cfg_dfg_extractor.py` (legacy/simple extractor)

Output model:
- Unified `SemanticGraph` (nodes + edges + symbol table + scopes), used as CPG-compatible graph.

### 4.1.1.3 Taint Tracking and Path Extraction Engine
Implemented in production pipeline:
- Rule-based source/sink matching from `queries/queries.json`
- BFS path traversal in `QueryExecutor` and `PathDiscovery`
- Multi-edge propagation across `DFG_FLOW`, `DFG_PARAM_PASS`, `DFG_RET`, `CALL_GRAPH`, `TAINT_FLOW`
- Minimal code slice extraction with line-context and file-location metadata

Also present:
- `TaintEngine` in `app/domain/analysis/taint_engine.py` (simpler legacy taint module)

### 4.1.1.4 LLM Classification Layer
- Providers integrated: OpenAI, GitHub Models, Anthropic, Groq (`semantic_engine/classifier/llm_service.py`)
- Unified wrapper implemented with:
  - retry/backoff
  - provider fallback chain
  - timeout control
  - prompt caching
- Structured JSON response parsing implemented.
- Fallback classification implemented when LLM is unavailable/disabled.

### 4.1.1.5 API Layer Implementation
Implemented route groups (11):
- `auth`, `dashboard`, `repositories`, `scans`, `scan`, `graphs`, `patches`, `reports`, `notifications`, `analysis`, `admin`

Status:
- Backend API is implemented.
- Frontend is not part of this repository.

### 4.1.1.6 Database and Persistence
Current implementation is hybrid:
- MongoDB (Motor): primary runtime storage for users, scans, logs, scan summaries.
- SQLAlchemy models exist for `users`, `repositories`, `scans`, `vulnerabilities`, `patches`, `reports`.

Correction to draft:
- The strict relational chain `User -> Repository -> Scan -> Vulnerability` is modeled conceptually but not fully enforced through SQLAlchemy relationships/foreign keys in current model classes.

### 4.1.1.7 Multi-File Repository and Cross-File Analysis
- Implemented in `multi_file_repo_graph.py`:
  - repository scanning
  - global symbol table
  - import/export linking
  - cross-file DFG propagation
  - route/auth decorator linkage
  - HTML/backend linkage

### 4.1.1.8 Query-Driven Vulnerability Rule System
- Large rule base in `queries/queries.json`
- Supports:
  - source/sink DFG rules
  - regex-based rules
  - file-pattern targeted rules
  - sanitizer and guard-aware filtering

### 4.1.1.9 Patch and Report Pipeline
- Patch module (`app/patch_module/*`) includes generation, validation, apply/export flow.
- Reporting endpoints and report service implemented.

## 4.1.2 Algorithm (Verified Against Code)

The following algorithms are implemented and functional, with notes where implementation differs from your draft pseudocode.

### AST Parsing Algorithm (Implemented, but tree-sitter based)
Input: Raw source code (Python/JS/TS)  
Output: `GraphNode` list + `AST_CHILD` edges + symbol table + scopes

Actual flow:
1. Detect language and load parser grammar.
2. Parse code with tree-sitter.
3. Traverse syntax tree recursively.
4. Create typed graph nodes (function, call, assignment, identifier, parameter, import, class, etc.).
5. Add `AST_CHILD` edges parent->child.
6. Build scope map and symbol references.
7. Build name-based call graph edges.
8. Return `SemanticGraph`.

Difference from your draft:
- Uses tree-sitter, not Python `ast` module.
- Includes scope/symbol/call-graph extraction, not only raw AST nodes/edges.

### Data Flow Graph Construction (Implemented)
Input: CPG/SemanticGraph  
Output: DFG edges (`DFG_FLOW`, `DFG_PARAM_PASS`, `DFG_RET`, etc.)

Actual flow:
1. Extract functions, parameters, return nodes, and call sites.
2. Build intraprocedural def-use edges.
3. Build argument->parameter edges.
4. Build return->caller edges.
5. Add closure/callback/tuple-unpack flows where applicable.
6. Annotate uncertainty/confidence metadata.
7. Merge DFG edges back into graph.

Difference from your draft:
- Goes beyond single map of last definition.
- Interprocedural support is implemented.

### Taint Tracking and Path Extraction (Implemented)
Input: Unified graph + query rules  
Output: candidate vulnerability paths + code slices

Actual flow:
1. Resolve source nodes from rule patterns.
2. Resolve sink nodes from rule patterns.
3. Select edge families based on pattern type (`DFG_FLOW`, `TAINT_FLOW`, etc.).
4. BFS from each source to sink(s) with max-depth/max-path limits.
5. Apply sanitizer/guard-aware scoring/filtering.
6. Extract minimal snippet + location metadata.
7. Deduplicate and rank findings.

Difference from your draft:
- Implemented in `QueryExecutor`/`PathDiscovery`; domain `TaintEngine` is simpler and not the main production path.

### LLM-Based Vulnerability Classification (Implemented)
Input: code slice + metadata (`rule`, `owasp`, `cwe`, source/sink labels)  
Output: structured classification object + merged final severity/confidence

Actual flow:
1. Build strict JSON-output prompt payload.
2. Call selected LLM provider.
3. Parse JSON response; normalize to internal schema.
4. If call fails, retry and fallback to alternate providers.
5. If all fail, return static fallback classification.
6. Combine static + LLM signals and keep only vulnerable/likely-vulnerable results.

## 4.2 Implementation Results (No ML Training)

This section reports implemented outputs without dataset training or benchmark claims.

### Implemented Outputs (Verified)
- AST/CPG generation implemented for Python, JavaScript, and TypeScript.
- Interprocedural DFG implemented (defs/uses, params, returns, call propagation).
- Unified graph merging implemented and used by scan pipeline.
- Taint/path detection implemented via rules and BFS traversal.
- Rules exist for SQL Injection, Command Injection, XSS, Path Traversal, and many additional categories.
- LLM layer returns structured JSON parsing into typed result objects.
- Fallback classification is triggered when LLM is unavailable/disabled.
- Scan APIs return vulnerability list with severity/confidence/location/evidence/analysis.

### Clarifications to Previous Draft
- "CFG linear edges created (statement-based)": partially true in legacy extractor; production scan path primarily relies on CPG + interprocedural DFG + path discovery/query execution.
- Numeric claims like "AST 50-200 nodes" or "3-15 hops deep" depend on input size and are not hardcoded guarantees.

## 4.3 Security Techniques Implemented

### 1. Authentication and Access Control
- JWT-based access tokens.
- Refresh endpoint (`/auth/refresh`).
- Role-aware authorization checks.
- OAuth login flows (Google, GitHub).
- Password reset token flow.

### 2. Input and Request Safety
- Pydantic schema validation on API payloads.
- Direct code scan line-limit validation (400 lines).
- Type-checked enums for scan mode and language.

### 3. Engine Safety
- Rules externalized in `queries.json` (controlled detection logic).
- Prompt format constrained to strict JSON schema output.
- Path deduplication and depth limits to prevent runaway traversal.
- Optional cycle detection in graph pipeline.

### 4. API/Platform Security
- CORS middleware enabled/configurable.
- Token-based protected routes via dependencies.
- Password hashing via bcrypt (`passlib`).

## 4.4 External APIs / SDKs Used

| API / SDK | Description | Purpose | Used In |
|---|---|---|---|
| FastAPI | Async Python web framework | API server and routing | `app/main.py`, `app/api/*` |
| SQLAlchemy 2.0 (Async) | Async ORM | Relational models/tables | `app/models/*`, `app/db/*` |
| Motor (MongoDB) | Async MongoDB driver | Primary runtime persistence | `app/db/mongo.py`, services |
| OpenAI API | GPT models | LLM classification | `semantic_engine/classifier/llm_service.py` |
| GitHub Models API | OpenAI-compatible endpoint | LLM classification | `semantic_engine/classifier/llm_service.py` |
| Anthropic API | Claude models | Optional fallback classification | `semantic_engine/classifier/llm_service.py` |
| Groq API | Low-latency hosted models | Optional fallback classification | `semantic_engine/classifier/llm_service.py` |
| tree-sitter (+ grammars) | Incremental parser | Multi-language CPG/AST extraction | `app/domain/analysis/cpg_parser.py` |
| python-jose | JWT encode/decode | Authentication token handling | `app/core/security.py` |
| passlib[bcrypt] | Password hashing | Secure password storage | `app/core/security.py` |

## Quickstart (for running backend)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -U pip
pip install -r requirements.txt
uvicorn app.main:app --reload
```

API docs: `http://127.0.0.1:8000/docs`  
Health: `GET /health`  
Base API prefix: `/api/v1`
