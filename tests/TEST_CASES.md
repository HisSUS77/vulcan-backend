# VULCAN — Full Test Case Documentation

> **100 total tests across 4 categories · 25 per category**
> Run with: `pytest tests/ -v`

---

## 5.1 Unit Testing

Unit testing verifies individual components in isolation to confirm they behave as
expected. Tests are written with **pytest** and require no database or network.

---

### Unit Test 1: `validateToken()` — Frontend Authentication Utility
**Objective:** Verify token validation correctly accepts valid JWTs and rejects malformed or expired tokens.

| No. | Test Case | Input | Expected Result | Actual Result |
|-----|-----------|-------|-----------------|---------------|
| UT-01 | Valid JWT accepted | `"eyJhbGciOi..."` (well-formed, in-date) | Returns `true` | Pass |
| UT-02 | Corrupted JWT rejected | `"abc.def.ghi"` | Returns `false` | Pass |
| UT-03 | Empty string rejected | `""` | Returns `false` | Pass |
| UT-04 | Expired JWT rejected | Valid structure but `exp` in the past | Returns `false` | Pass |

---

### Unit Test 2: `parse_code()` — Backend AST Parser
**Objective:** Ensure the parser generates a valid AST for correct input and handles invalid syntax without crashing.

| No. | Test Case | Input | Expected Result | Actual Result |
|-----|-----------|-------|-----------------|---------------|
| UT-05 | Valid JS function | `"function x(a){return a;}"` | AST generated | Pass |
| UT-06 | Invalid syntax | `"function { return }"` | Parse error caught safely; no crash | Pass |
| UT-07 | Empty code string | `""` | Returns empty AST structure | Pass |

---

### Unit Test 3: `detect_sinks()` — Taint Engine Module
**Objective:** Confirm that vulnerable sink functions are detected correctly.

| No. | Test Case | Code Snippet | Expected Output | Actual Result |
|-----|-----------|--------------|-----------------|---------------|
| UT-08 | `eval()` sink detected | `"eval(userInput)"` | Sink detected: `eval` | Pass |
| UT-09 | `child_process.exec()` detected | `"exec(cmd)"` | Sink detected: `exec` | Pass |
| UT-10 | No sink present | `"let x = 5;"` | No sinks detected | Pass |

---

### Unit Test 4: Cross-File Flow Resolution — Multi-File Repository Parsing
**Objective:** Verify that import/export links produce valid cross-file data-flow paths.

| No. | Test Case / Script | Input | Expected Result | Actual Result |
|-----|-------------------|-------|-----------------|---------------|
| UT-11 | `test_cross_file_flow.py` | Multi-file repo fixture | Import → export resolution succeeds | Pass |
| UT-12 | `test_import_export_patterns.py` | ES module patterns | Symbols resolved correctly | Pass |
| UT-13 | `test_reexport_chain.py` | Chained re-exports | Final symbol trace preserved | Pass |

---

### Unit Test 5: JS/TS Export Variants — Multi-Language Tree-Sitter Parsers
**Objective:** Validate support for CommonJS and TypeScript export patterns.

| No. | Test Case / Script | Input | Expected Result | Actual Result |
|-----|-------------------|-------|-----------------|---------------|
| UT-14 | `test_commonjs_exports.py` | `module.exports` usage | Export captured | Pass |
| UT-15 | `test_ts_export_equals.py` | `export =` syntax | Export captured | Pass |
| UT-16 | `test_js_flows.py` | JS data-flow snippets | Flow edges generated | Pass |

---

### Unit Test 6: Patch Module Validators — Patch Generation and Validator Module
**Objective:** Ensure patch validation components correctly detect invalid or unsafe patches.

| No. | Test Case / Script | Component | Expected Result | Actual Result |
|-----|-------------------|-----------|-----------------|---------------|
| UT-17 | `test_syntax_validator.py` | Syntax validator | Invalid patches rejected | Pass |
| UT-18 | `test_semantic_validator.py` | Semantic validator | Semantic regressions detected | Pass |
| UT-19 | `test_orchestrator.py` | Patch orchestrator | Flow executes with guard checks | Pass |

---

### Unit Test 7: `get_password_hash()` / `verify_password()` — Security Module
**Objective:** Verify bcrypt hashing produces secure, non-reversible hashes and verification is accurate.
**Script:** `tests/unit/test_security.py · TestPasswordHashing`

| No. | Test Case | Input | Expected Result | Actual Result |
|-----|-----------|-------|-----------------|---------------|
| UT-20 | Hash is not plaintext | `"secret123"` | Hash ≠ input string; starts with `$2b$` | Pass |
| UT-21 | Same password yields different hashes | `"password"` hashed twice | `hash1 != hash2` (bcrypt salt) | Pass |
| UT-22 | Correct password verifies | `verify_password("correct", hash)` | Returns `True` | Pass |

---

### Unit Test 8: `create_access_token()` / `decode_token()` — JWT Security Module
**Objective:** Confirm JWTs are created with correct claims and rejected when tampered or expired.
**Script:** `tests/unit/test_security.py · TestJWTCreation / TestJWTDecoding`

| No. | Test Case | Input | Expected Result | Actual Result |
|-----|-----------|-------|-----------------|---------------|
| UT-23 | Token contains correct subject | `create_access_token("user-abc")` | `payload["sub"] == "user-abc"` | Pass |
| UT-24 | Tampered token raises `JWTError` | Valid token with last 5 chars replaced | `JWTError` raised | Pass |
| UT-25 | Expired token raises `JWTError` | `create_token("u1", expires_minutes=-1)` | `JWTError` raised on decode | Pass |

---

## 5.2 Functional Testing

Functional testing validates that complete user-facing features behave correctly end-to-end. Tests exercise the full request/response cycle through the FastAPI application with a mocked MongoDB and mocked LLM pipeline.

---

### Functional Test 1: User Registration and Login Flow
**Objective:** Verify a new user can register, log in, and receive a valid JWT.
**Script:** `tests/functional/test_scan_workflow.py · TestRegisterLoginScanWorkflow`

| No. | Test Case | Steps | Expected Result | Actual Result |
|-----|-----------|-------|-----------------|---------------|
| FT-01 | Register new account | POST `/auth/register` with email + password | HTTP 201; user object returned; `role = "normal"` | Pass |
| FT-02 | Login with valid credentials | POST `/auth/login` with same email/password | HTTP 200; `access_token` present in response | Pass |
| FT-03 | Login with wrong password | POST `/auth/login` with incorrect password | HTTP 401; no token issued | Pass |
| FT-04 | Access profile with token | GET `/auth/me` with Bearer token | HTTP 200; correct email and role in response | Pass |
| FT-05 | Token required for protected route | GET `/auth/me` without Authorization header | HTTP 401; request rejected | Pass |

---

### Functional Test 2: Code Vulnerability Scan
**Objective:** Verify the scan pipeline accepts code, detects vulnerabilities, and returns structured results.
**Script:** `tests/functional/test_scan_workflow.py · TestRegisterLoginScanWorkflow`

| No. | Test Case | Input Code | Expected Result | Actual Result |
|-----|-----------|------------|-----------------|---------------|
| FT-06 | Scan vulnerable Python code | f-string SQL query with user input | HTTP 200; `vulnerabilities_found ≥ 1`; `scan_id` present | Pass |
| FT-07 | Scan clean code | `x = 1` | HTTP 200; `vulnerabilities_found = 0` | Pass |
| FT-08 | Scan JavaScript code | `const id = req.query.id` | HTTP 200; scan completes successfully | Pass |
| FT-09 | Scan missing required field | POST with no `code` field | HTTP 422 validation error | Pass |
| FT-10 | Scan result contains severity breakdown | Vulnerable Flask app code | Response includes `by_severity` with critical/high/medium/low counts | Pass |

---

### Functional Test 3: Kill Chain Visualization
**Objective:** Verify vulnerabilities from a completed scan are correctly mapped to MITRE ATT&CK stages.
**Script:** `tests/functional/test_scan_workflow.py · TestScanToKillChainWorkflow`

| No. | Test Case | Scan Vulnerabilities | Expected Result | Actual Result |
|-----|-----------|---------------------|-----------------|---------------|
| FT-11 | Kill chain for completed scan | 3 vulns (SQLi, Hardcoded Secret, Path Traversal) | HTTP 200; exactly 8 stages returned; `total_vulns = 3` | Pass |
| FT-12 | High-severity scan has high blast radius | 5 critical vulnerabilities across 5 stages | `blast_radius > 50` | Pass |
| FT-13 | Kill chains generated for multi-stage scan | SQLi + Command Injection + XSS | `len(kill_chains) ≥ 1`; each chain has name, probability, stages | Pass |

---

### Functional Test 4: Report Generation
**Objective:** Confirm that completed scans can be exported in all supported report formats.
**Script:** `tests/functional/test_scan_workflow.py · TestScanToReportWorkflow`

| No. | Test Case | Format | Expected Result | Actual Result |
|-----|-----------|--------|-----------------|---------------|
| FT-14 | Generate SARIF report | GET `/reports/{scan_id}/sarif` | HTTP 200; SARIF 2.1.0 structure returned | Pass |
| FT-15 | Generate CSV report | GET `/reports/{scan_id}/csv` | HTTP 200; CSV rows with vulnerability fields | Pass |
| FT-16 | Report for non-existent scan | GET `/reports/bad-id/html` | HTTP 404 | Pass |

---

### Functional Test 5: Repository Management
**Objective:** Verify full CRUD lifecycle for repository resources.
**Script:** `tests/integration/test_repositories_api.py`

| No. | Test Case | Action | Expected Result | Actual Result |
|-----|-----------|--------|-----------------|---------------|
| FT-17 | List repositories — empty | GET `/repositories/` with no repos in DB | HTTP 200; empty array `[]` | Pass |
| FT-18 | Create repository | POST `/repositories/` with name and URL | HTTP 201; repository object with `id` returned | Pass |
| FT-19 | Delete repository | DELETE `/repositories/{id}` for owned repo | HTTP 200/204; subsequent GET returns 404 | Pass |

---

### Functional Test 6: Benchmark Workflow
**Objective:** Verify the benchmark pipeline seeds test cases, runs detection, and produces metrics.
**Script:** `tests/integration/test_benchmark_api.py`

| No. | Test Case | Action | Expected Result | Actual Result |
|-----|-----------|--------|-----------------|---------------|
| FT-20 | Run benchmark with seeded cases | POST `/benchmark/runs` (enable_llm: false) | HTTP 200; response contains `tp`, `fp`, `fn`, `tn`, `f1`, `precision`, `recall` | Pass |
| FT-21 | Benchmark run stored in DB | POST `/benchmark/runs`, then GET `/benchmark/runs/{id}` | Stored run retrievable; metrics match | Pass |
| FT-22 | Leaderboard sorted by F1 | GET `/benchmark/leaderboard` with 3 runs | HTTP 200; entries sorted descending by `best_f1` | Pass |

---

### Functional Test 7: Dashboard and Attack Surface
**Objective:** Verify aggregation endpoints return correct summaries after scans.
**Script:** `tests/functional/test_scan_workflow.py · TestDashboardAfterScans`

| No. | Test Case | Action | Expected Result | Actual Result |
|-----|-----------|--------|-----------------|---------------|
| FT-23 | Dashboard summary returns stats | GET `/dashboard/summary` with completed scans in DB | HTTP 200; dict with scan counts and severity totals | Pass |
| FT-24 | Recent scans list | GET `/dashboard/recent-scans` | HTTP 200; array of most recent scan summaries | Pass |
| FT-25 | Token refresh produces valid new token | POST `/auth/refresh` with valid token | HTTP 200; new `access_token` in response | Pass |

---

## 5.3 Business Rule Testing

Business rule testing verifies that domain-level policies — access control, detection
accuracy, scoring, and data scoping — are correctly enforced by the system.

---

### Business Rule Test 1: Role-Based Access Control (RBAC)
**Objective:** Confirm that endpoints enforce role permissions: normal, premium, and admin.
**Script:** `tests/business_rules/test_role_access.py`

| No. | Business Rule | Test Action | Expected Enforcement | Actual Result |
|-----|--------------|-------------|---------------------|---------------|
| BR-01 | Normal user cannot access admin panel | Normal user calls GET `/admin/users` | HTTP 403 or 404 | Pass |
| BR-02 | Admin user can list all users | Admin user calls GET `/admin/users` | HTTP 200; user list returned | Pass |
| BR-03 | Premium user can access patch endpoint | Premium user calls GET `/patches/{id}` | HTTP 200 or 404 (auth passed) | Pass |
| BR-04 | Normal user cannot promote another user | Normal user calls PATCH `/admin/users/{id}` | HTTP 403 or 404 | Pass |
| BR-05 | Unauthenticated user blocked from all protected routes | 7 key endpoints called without token | All return HTTP 401 | Pass |

---

### Business Rule Test 2: True-Positive Vulnerability Detection
**Objective:** Confirm that known-vulnerable code patterns are always detected.
**Script:** `tests/business_rules/test_vulnerability_detection.py`

| No. | Rule | Vulnerable Code | Expected Detection | Actual Result |
|-----|------|-----------------|-------------------|---------------|
| BR-06 | SQL Injection — f-string | `f"SELECT * FROM users WHERE id={uid}"` | Detected (CWE-89) | Pass |
| BR-07 | Command Injection — shell=True | `subprocess.run(cmd, shell=True)` | Detected (CWE-78) | Pass |
| BR-08 | Path Traversal — Flask send_file | `send_file(request.args.get('name'))` | Detected (CWE-22) | Pass |
| BR-09 | Weak Crypto — MD5 password hash | `hashlib.md5(password)` | Detected (CWE-327) | Pass |
| BR-10 | Hardcoded Secret — JWT key | `JWT_SECRET = "my-secret"` | Detected (CWE-798) | Pass |

---

### Business Rule Test 3: False-Positive Prevention (Safe Code Must Not Fire)
**Objective:** Confirm that safe alternatives to vulnerable patterns are not flagged.
**Script:** `tests/business_rules/test_vulnerability_detection.py`

| No. | Rule | Safe Code | Expected Result | Actual Result |
|-----|------|-----------|-----------------|---------------|
| BR-11 | Command Injection — safe list form | `subprocess.run(['ls', '-la'])` | Not detected | Pass |
| BR-12 | Deserialization — yaml.safe_load | `yaml.safe_load(data)` | Not detected | Pass |
| BR-13 | Deserialization — JSON.parse | `JSON.parse(body)` | Not detected | Pass |
| BR-14 | Debug Mode — debug=False | `app.run(debug=False)` | Not detected | Pass |
| BR-15 | Insecure Cookie — secure=True set | `set_cookie('s', token, secure=True)` | Not detected | Pass |

---

### Business Rule Test 4: Benchmark Scoring Rules
**Objective:** Verify TP/FP/FN/TN counting is correct and metrics are accurately derived.
**Script:** `tests/business_rules/test_benchmark_scoring.py`

| No. | Business Rule | Scenario | Expected Score | Actual Result |
|-----|--------------|----------|----------------|---------------|
| BR-16 | Detected vulnerable case = TP | Label=`vulnerable`, scanner fires | `outcome = "TP"` | Pass |
| BR-17 | Detected safe case = FP | Label=`safe`, scanner fires | `outcome = "FP"` | Pass |
| BR-18 | Missed vulnerable case = FN | Label=`vulnerable`, scanner silent | `outcome = "FN"` | Pass |
| BR-19 | F1 = 0 when zero TPs | All cases are FP + TN | `f1 = 0.0` | Pass |
| BR-20 | Leaderboard trend shows ↑ when F1 improves | Latest run F1 higher than previous | `trend = "↑"` | Pass |

---

### Business Rule Test 5: Security and Data-Scoping Policies
**Objective:** Verify that security boundaries — token validity, data ownership, and role escalation — are enforced.
**Script:** `tests/business_rules/test_role_access.py · TestRoleEscalationProtection`

| No. | Business Rule | Test Scenario | Expected Enforcement | Actual Result |
|-----|--------------|---------------|---------------------|---------------|
| BR-21 | Expired JWT is rejected | Token with `exp` 1 minute in the past | HTTP 401 on any protected endpoint | Pass |
| BR-22 | User cannot self-promote to admin | Normal user calls PATCH `/admin/users/{own_id}` with `role=admin` | HTTP 403 or 404 | Pass |
| BR-23 | Forged admin claim in JWT does not grant access | Token payload has `role=admin` but DB record says `normal` | Server-side DB role checked; access denied | Pass |
| BR-24 | Weak crypto 4096-bit RSA not flagged | `RSA.generate(4096)` | No detection (key size is adequate) | Pass |
| BR-25 | yaml.load with SafeLoader not flagged | `yaml.load(data, Loader=SafeLoader)` | No detection (safe loader used) | Pass |

---

## 5.4 Integration Testing

Integration testing verifies that multiple system components work correctly together through the full HTTP request/response cycle, including authentication, database interaction, and service orchestration.

---

### Integration Test 1: Authentication API — `/api/v1/auth/*`
**Objective:** Verify all authentication endpoints function correctly end-to-end with MongoDB.
**Script:** `tests/integration/test_auth_api.py`

| No. | Endpoint | Method / Input | Expected Response | Actual Result |
|-----|----------|----------------|-------------------|---------------|
| IT-01 | `POST /auth/register` | `{email, password, full_name}` | HTTP 201; user object with `id`, `role="normal"` | Pass |
| IT-02 | `POST /auth/register` duplicate email | Same email twice | HTTP 409 Conflict | Pass |
| IT-03 | `POST /auth/login` valid credentials | Correct email + password | HTTP 200; `access_token` + `token_type: "bearer"` | Pass |
| IT-04 | `POST /auth/login` wrong password | Correct email, wrong password | HTTP 401 Unauthorized | Pass |
| IT-05 | `GET /auth/me` with Bearer token | Valid JWT in Authorization header | HTTP 200; `email`, `role` returned; no `hashed_password` | Pass |

---

### Integration Test 2: Authentication API — Password Reset and Token Refresh
**Objective:** Verify reset flow and token refresh work correctly.
**Script:** `tests/integration/test_auth_api.py · TestPasswordReset / TestRefreshToken`

| No. | Endpoint | Input | Expected Response | Actual Result |
|-----|----------|-------|-------------------|---------------|
| IT-06 | `POST /auth/forgot-password` unknown email | Non-registered email | HTTP 200 always (prevents account enumeration) | Pass |
| IT-07 | `POST /auth/validate-reset-token` invalid token | `{token: "bad-token"}` | HTTP 200; `{valid: false}` | Pass |
| IT-08 | `POST /auth/reset-password` invalid token | `{token: "bad", new_password: "..."}` | HTTP 400 Bad Request | Pass |
| IT-09 | `POST /auth/refresh` authenticated | Valid Bearer token | HTTP 200; new `access_token` issued | Pass |
| IT-10 | `POST /auth/logout` authenticated | Valid Bearer token | HTTP 200; `{message: "Logged out"}` | Pass |

---

### Integration Test 3: Scan API — `/api/v1/scan/*` and `/api/v1/scans/*`
**Objective:** Verify code submission, scan status, and scan management endpoints.
**Script:** `tests/integration/test_scan_api.py`

| No. | Endpoint | Input | Expected Response | Actual Result |
|-----|----------|-------|-------------------|---------------|
| IT-11 | `POST /scan/scan` valid Python code | `{code, language: "python", filename}` | HTTP 200; `scan_id` in body; `vulnerabilities_found` field present | Pass |
| IT-12 | `POST /scan/scan` missing `language` | `{code: "x=1"}` | HTTP 422 Validation Error | Pass |
| IT-13 | `POST /scan/scan` unauthenticated | No Authorization header | HTTP 401 Unauthorized | Pass |
| IT-14 | `GET /scans/{scan_id}/status` existing | Valid `scan_id` | HTTP 200; `{status: "COMPLETED"}` | Pass |
| IT-15 | `GET /scans/{scan_id}/status` missing | Unknown `scan_id` | HTTP 404 Not Found | Pass |

---

### Integration Test 4: Kill Chain API — `/api/v1/kill-chain/*`
**Objective:** Verify kill chain endpoint maps scan vulnerabilities to MITRE ATT&CK stages.
**Script:** `tests/integration/test_kill_chain_api.py`

| No. | Endpoint | Setup | Expected Response | Actual Result |
|-----|----------|-------|-------------------|---------------|
| IT-16 | `GET /kill-chain/{scan_id}` existing scan | Scan with 3 vulns (SQLi, Secret, Path Traversal) | HTTP 200; 8 stages; `total_vulns = 3`; `stages_hit ≥ 1` | Pass |
| IT-17 | `GET /kill-chain/{scan_id}` missing scan | Unknown `scan_id` | HTTP 404 Not Found | Pass |
| IT-18 | `GET /kill-chain/{scan_id}` SQL Injection mapped correctly | Scan with SQLi only | `initial_access` stage is `active = true`, `vuln_count = 1` | Pass |
| IT-19 | `GET /kill-chain/{scan_id}` blast radius between 0–100 | Multi-vuln scan | `0 ≤ blast_radius ≤ 100`; type is integer | Pass |
| IT-20 | `GET /kill-chain/{scan_id}` unauthenticated | No token | HTTP 401 Unauthorized | Pass |

---

### Integration Test 5: Benchmark API — `/api/v1/benchmark/*`
**Objective:** Verify benchmark test case management and run execution against mocked pipeline.
**Script:** `tests/integration/test_benchmark_api.py`

| No. | Endpoint | Input | Expected Response | Actual Result |
|-----|----------|-------|-------------------|---------------|
| IT-21 | `GET /benchmark/test-cases` | 5 seeded cases in DB | HTTP 200; array of 5 test case objects | Pass |
| IT-22 | `POST /benchmark/test-cases` | Valid test case JSON | HTTP 200/201; created case with `id` field | Pass |
| IT-23 | `POST /benchmark/runs` | `{enable_llm: false}` with seeded cases | HTTP 200; body contains `tp`, `fp`, `fn`, `tn`, `precision`, `recall`, `f1` | Pass |
| IT-24 | `GET /benchmark/leaderboard` | 2 runs with different models | HTTP 200; array sorted by `best_f1` descending | Pass |
| IT-25 | `GET /admin/users` normal user | Normal user token | HTTP 403 or 404; access denied | Pass |

---

## Summary

| Category | Tests | Scope |
|----------|-------|-------|
| Unit Testing | 25 | Individual functions: token validation, AST parsing, sink detection, cross-file flow, password hashing, JWT, benchmark metrics |
| Functional Testing | 25 | End-to-end user journeys: register→login→scan→kill-chain→report, repository CRUD, benchmark workflow, dashboard |
| Business Rule Testing | 25 | Domain policies: RBAC, true-positive detection, false-positive prevention, benchmark scoring, data scoping |
| Integration Testing | 25 | API layer: Auth, Scan, Kill Chain, Benchmark, Admin endpoints with full request/response validation |
| **Total** | **100** | |

---

### How to Run

```bash
# All 100 tests
pytest tests/ -v

# By category
pytest tests/unit/            -v    # Unit tests
pytest tests/functional/      -v    # Functional tests
pytest tests/business_rules/  -v    # Business rule tests
pytest tests/integration/     -v    # Integration tests

# By feature
pytest tests/ -k "kill_chain"       # Kill chain tests only
pytest tests/ -k "benchmark"        # Benchmark tests only
pytest tests/ -k "auth"             # Authentication tests only

# With coverage
pytest tests/ --cov=app --cov=semantic_engine --cov-report=term-missing
```

### Test Infrastructure

| Tool | Purpose |
|------|---------|
| `pytest` | Test runner |
| `pytest-asyncio` | Async service method testing |
| `mongomock` | In-memory MongoDB (no real DB required) |
| `FastAPI TestClient` | HTTP endpoint testing without running a server |
| `unittest.mock.patch` | Mock LLM pipeline, email service, external APIs |
| `httpx` | Async HTTP client for future async integration tests |
