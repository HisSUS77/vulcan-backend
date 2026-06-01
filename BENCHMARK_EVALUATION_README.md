# VULCAN Benchmark Evaluation

This document tracks benchmark results for VULCAN against the CodeQL security fixture corpus, including per-CWE root-cause analysis, engine improvement history, and targets for each release iteration.

## 1. Benchmark Configuration

```text
Tool: VULCAN
Mode: Static-only
Dataset: Curated CodeQL security fixture corpus
Scope: Six supported high-value CWE families
Families: CWE-22, CWE-78, CWE-79, CWE-89, CWE-918, CWE-94
Exploit generation: Disabled during benchmark
LLM classification: Disabled during benchmark
Line tolerance: 2 lines
Result persistence: MongoDB benchmark_runs collection
Benchmark job persistence: MongoDB benchmark_jobs collection
```

## 2. Benchmark History

### Baseline — Initial release

```text
TP: 469 | FP: 38 | FN: 3,350 | Total: 3,857
Precision: 92.5% | Recall: 12.3% | F1: 21.7%
Runtime: 149.3 seconds
```

### v2 — Sink registry expansion (XSS + SQLi)

Added `bypassSecurityTrustHtml`, specialized ORM query wrappers, CWE-94 regex depth.

```text
TP: 634 | FP: 50 | FN: 2,964 | TN: 1
Precision: 92.69% | Recall: 17.62% | F1: 29.61%
```

Per-CWE breakdown:

| CWE | TP | FP | FN | Precision | Recall | F1 | Root Cause of Low Recall |
|---|---:|---:|---:|---:|---:|---:|---|
| CWE-22 Path Traversal | 46 | 3 | 594 | 93.88% | 7.19% | 13.35% | Safe-pattern over-suppression; narrow regex coverage |
| CWE-78 Cmd Injection | 60 | 4 | 654 | 93.75% | 8.40% | 15.42% | `subprocess([...])` incorrectly marked safe; limited shell patterns |
| CWE-79 XSS | 307 | 34 | 1,023 | 90.03% | 23.08% | 36.74% | Missing res.write / insertAdjacentHTML / template-literal sinks |
| CWE-89 SQLi | 94 | 5 | 355 | 94.95% | 20.94% | 34.31% | Missing SQLAlchemy text(), Django extra(), indirect string building |
| CWE-918 SSRF | 29 | 0 | 165 | 100.00% | 14.95% | 26.01% | Missing async-client patterns, node-fetch/got, urljoin chains |
| CWE-94 Code Injection | 98 | 4 | 173 | 96.08% | 36.16% | 52.55% | Best performer; re.compile suppressor correctly scoped |
| **Overall** | **634** | **50** | **2,964** | **92.69%** | **17.62%** | **29.61%** | |

### v3 — Recall engineering (current iteration)

**Root-cause fixes applied:**

1. **`_SUBPROCESS_LIST` safe pattern** (classifier.py) — Previously matched ANY `subprocess.run([...])` call and marked it safe. This incorrectly suppressed `subprocess.run(['sh', '-c', user_input])` and similar argument-injection patterns. Fixed: now only matches when the list contains **exclusively string literals**. Variable elements leave the pattern unmatched → correctly flagged.

2. **`_PATH_NORMPATH_SAFE + _PATH_STARTSWITH` safe pattern** (classifier.py) — Previously fired when `os.path.normpath` appeared anywhere AND `startswith` appeared anywhere in the same snippet — even in unrelated code. `normpath` alone does NOT prevent path traversal (no symlink resolution). Fixed: replaced with `_PATH_REALPATH_PREFIX` which requires `realpath`/`abspath` (strong canonicalization) and a `startswith` prefix check to appear **in close proximity**, which is the only pattern that actually prevents traversal.

3. **CWE-22 regex + sinks** (queries.json) — Added 8 new regex patterns covering: `open(request.args...)` direct calls, `os.open`/`io.open`/`aiofiles.open`, `os.makedirs`/`os.remove` family, `pathlib.Path(request...)`, JS `fs.*` with `req.query/params/body`, `send_file`/`send_from_directory` with request access. Added 13 new sinks including `os.open`, `io.open`, `aiofiles.open`, `os.makedirs`, `fs.createReadStream`, `fs.appendFile`, `send_from_directory`.

4. **CWE-78 regex + sources + sinks** (queries.json) — Added 6 new regex patterns: subprocess list with variable args, `os.system(variable)` with string operations, `os.popen(variable)`, `subprocess.check_output` with shell/concatenation, `commands.getoutput/getstatusoutput`, JS `child_process.*` with req variables. Added `commands.getoutput`, `commands.getstatusoutput`, `subprocess.check_output` sinks. Added `request.values`, `request.data`, `req.headers` sources.

5. **CWE-79 regex + sinks** (queries.json) — Added 7 new regex patterns: `res.write` with user input, `insertAdjacentHTML`, template-literal injection chained to dangerous sinks, `element.innerHTML =`, `.setAttribute(href/src/action, ...)`, direct Flask `make_response` with user data. Added `res.write`, `res.end`, `insertAdjacentHTML`, `bypassSecurityTrustScript`, `bypassSecurityTrustUrl` sinks.

6. **CWE-89 regex** (queries.json) — Added 5 new patterns: SQLAlchemy `text()` with user data, Django `extra(where=[...])`, DB client `.execute`/`.query` with f-strings or template literals, `cursor.execute` with `+` concatenation, ORM `filter`/`where` with request data.

7. **CWE-918 regex + sources** (queries.json) — Added 6 new patterns: aiohttp/httpx async client patterns, `urllib.parse.urljoin` chained to HTTP fetch, `got`/`node-fetch`/`superagent`/`needle`, `new URL(req...)` then fetch, `requests.get(variable)`. Added `webhook`, `endpoint`, `redirect_url`, `request.values`, `request.data`, `req.headers` sources.

**Projected targets after v3 (re-run benchmark to confirm):**

| CWE | Baseline Recall | Target Recall | Target F1 | Min Precision |
|---|---:|---:|---:|---:|
| CWE-22 | 7.19% | ≥ 55% | ≥ 70% | ≥ 85% |
| CWE-78 | 8.40% | ≥ 55% | ≥ 70% | ≥ 85% |
| CWE-79 | 23.08% | ≥ 55% | ≥ 70% | ≥ 85% |
| CWE-89 | 20.94% | ≥ 50% | ≥ 65% | ≥ 85% |
| CWE-918 | 14.95% | ≥ 40% | ≥ 57% | ≥ 85% |
| CWE-94 | 36.16% | ≥ 45% | ≥ 60% | ≥ 90% |
| **Overall** | **17.62%** | **≥ 55%** | **≥ 70%** | **≥ 85%** |

## 3. Per-CWE Results Table

### 3.1 VULCAN Per-CWE Results (v2 baseline — pre-v3 improvements)

| Tool | Dataset | CWE | TP | FP | FN | TN | Precision | Recall | F1 | FP/KLOC | Runtime | Peak Memory |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| VULCAN | CodeQL curated corpus | CWE-22 | 46 | 3 | 594 | TBD | 93.88% | 7.19% | 13.35% | TBD | TBD | TBD |
| VULCAN | CodeQL curated corpus | CWE-78 | 60 | 4 | 654 | TBD | 93.75% | 8.40% | 15.42% | TBD | TBD | TBD |
| VULCAN | CodeQL curated corpus | CWE-79 | 307 | 34 | 1,023 | TBD | 90.03% | 23.08% | 36.74% | TBD | TBD | TBD |
| VULCAN | CodeQL curated corpus | CWE-89 | 94 | 5 | 355 | TBD | 94.95% | 20.94% | 34.31% | TBD | TBD | TBD |
| VULCAN | CodeQL curated corpus | CWE-918 | 29 | 0 | 165 | TBD | 100.00% | 14.95% | 26.01% | TBD | TBD | TBD |
| VULCAN | CodeQL curated corpus | CWE-94 | 98 | 4 | 173 | TBD | 96.08% | 36.16% | 52.55% | TBD | TBD | TBD |
| VULCAN | CodeQL curated corpus | Overall | 634 | 50 | 2,964 | 1 | 92.69% | 17.62% | 29.61% | TBD | TBD | TBD |

### 3.2 VULCAN Per-CWE Results (v3 — after recall improvements, re-run required)

| Tool | Dataset | CWE | TP | FP | FN | TN | Precision | Recall | F1 | FP/KLOC | Runtime | Peak Memory |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| VULCAN | CodeQL curated corpus | CWE-22 | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| VULCAN | CodeQL curated corpus | CWE-78 | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| VULCAN | CodeQL curated corpus | CWE-79 | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| VULCAN | CodeQL curated corpus | CWE-89 | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| VULCAN | CodeQL curated corpus | CWE-918 | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| VULCAN | CodeQL curated corpus | CWE-94 | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| VULCAN | CodeQL curated corpus | Overall | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD |

### 2.2 Baseline Tool Results

Add baseline tool results here after running equivalent experiments.

| Tool | Dataset | CWE | TP | FP | FN | TN | Precision | Recall | F1 | FP/KLOC | Runtime | Peak Memory |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| CodeQL | Same corpus/scope | Overall | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| Semgrep | Same corpus/scope | Overall | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| Snyk | Same corpus/scope | Overall | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD |

## 3. Statistical Analysis

Current raw VULCAN counts:

```text
TP = 634
FP = 50
FN = 2964
TN = 1
```

Statistical tests still to run:

| Comparison | Dataset | Metric | Test | Statistic | p-value | Significant? | Interpretation |
|---|---|---|---|---:|---:|---|---|
| VULCAN vs CodeQL | Curated CodeQL corpus | Paired detection disagreement | McNemar | TBD | TBD | TBD | TBD |
| VULCAN vs Semgrep | Curated CodeQL corpus | Paired detection disagreement | McNemar | TBD | TBD | TBD | TBD |
| VULCAN vs Snyk | Curated CodeQL corpus | Paired detection disagreement | McNemar | TBD | TBD | TBD | TBD |
| VULCAN before vs after recall improvements | Curated CodeQL corpus | Per-CWE F1 | Paired t-test or Wilcoxon | TBD | TBD | TBD | TBD |

Required inputs for McNemar:

```text
n01 = cases missed by VULCAN but detected by baseline
n10 = cases detected by VULCAN but missed by baseline
```

Required inputs for paired metric tests:

```text
Per-CWE precision values
Per-CWE recall values
Per-CWE F1 values
Same dataset and same scoring method for each compared tool
```

## 4. Experimental Protocol

### 4.1 Reproducibility Metadata

| Item | Value |
|---|---|
| VULCAN commit hash | TBD |
| Backend commit hash | TBD |
| Frontend commit hash | TBD |
| Query/rule-set version | Current `queries/queries.json`; commit TBD |
| Dataset | Local CodeQL security fixtures under `Security-python` and `Security_ javascript` |
| Dataset commit/source | TBD |
| Included CWE families | CWE-22, CWE-78, CWE-79, CWE-89, CWE-918, CWE-94 |
| Excluded CWE families | TBD; document unsupported or out-of-scope families |
| CVE IDs | TBD if real-world CVE repositories are used |
| Ground truth | CodeQL `.expected` files with `#select` rows plus explicit `$ MISSING: Alert` comments |
| Annotation method | CodeQL fixture labels; manual review TBD |
| Line tolerance | 2 lines |
| Deduplication | Canonical CWE + repo-relative file + start line |
| LLM enabled? | No |
| Exploit generation enabled? | No |
| Max path length | 30 |
| Max paths per rule | 50 |
| Max candidate paths | 80 |

### 4.2 Hardware and Software

Fill before final submission:

| Component | Value |
|---|---|
| CPU | TBD |
| RAM | TBD |
| GPU | TBD / None |
| Disk | TBD |
| Operating system | Windows, exact version TBD |
| Python version | TBD |
| Node version | TBD |
| MongoDB version | TBD |
| Browser used for frontend | TBD |

### 4.3 Benchmark Execution

The benchmark is executed asynchronously from the frontend.

Backend endpoints:

```text
POST /api/v1/benchmark/run-codeql-corpus-job
GET  /api/v1/benchmark/jobs/{job_id}
GET  /api/v1/benchmark/runs/{run_id}
GET  /api/v1/benchmark/runs?run_type=codeql-corpus
```

Persistence:

```text
benchmark_jobs stores queued/running/completed/failed job state.
benchmark_runs stores the final BenchmarkRun result.
```

Targeted benchmark roots:

```text
Security-python/CWE-089-SqlInjection
Security_ javascript/CWE-089
Security-python/CWE-078-CommandInjection
Security_ javascript/CWE-078
Security-python/CWE-079-XSS
Security_ javascript/CWE-079
Security-python/CWE-022-PathTraversal
Security_ javascript/CWE-022
Security-python/CWE-918-SSRF
Security_ javascript/CWE-918
Security-python/CWE-094-CodeInjection
Security_ javascript/CWE-094
```

## 5. Patch Validation Report

Patch validation results are not yet filled.

Required metrics:

```text
Patch Success Rate = successful patches / attempted patches
Security Fix Rate = findings removed after patch / patched findings
Regression Rate = patches causing test failure / successful patches
```

Suggested table:

| Finding ID | CWE | Patch Applied? | Security Re-scan Passed? | Tests Passed? | Manual Verdict | Notes |
|---|---|---|---|---|---|---|
| TBD | TBD | TBD | TBD | TBD | TBD | TBD |

Evidence to collect:

- Number of vulnerabilities selected for patching.
- Number of patches generated.
- Number of patches successfully applied.
- Test-suite result before patch.
- Test-suite result after patch.
- VULCAN re-scan result after patch.
- Manual review notes.
- Runtime for patch generation and validation.

## 6. Independent Validation

Prepare this package for an external third-party auditor:

```text
/source-code
/benchmark-data
/benchmark-manifests
/raw-results
/metric-scripts
/patch-validation-results
/environment-notes
/README-reproduction.md
```

Include:

- Source code repository access.
- Exact commit hash used for evaluation.
- Benchmark dataset or sample data.
- Curated manifest of included/excluded benchmark cases.
- Benchmark runner instructions.
- Environment setup instructions.
- Expected output files.
- Raw benchmark result exports from MongoDB.
- Scripts used to calculate metrics.
- Manual annotation sheets, if used.
- Private repository access instructions, if real private repositories are used.
- Auditor contact/access procedure.
- Known limitations and threats to validity.

## 7. Limitations and Threats to Validity

Known current limitations:

- v3 recall targets (≥55% overall) require benchmark re-run to confirm; projected from pattern coverage analysis.
- Some CodeQL expected rows represent fine-grained flow locations (individual taint-propagation steps) rather than one human-level vulnerability, which inflates FN counts relative to real-world impact.
- CWE-22 and CWE-78 recall improvements depend heavily on DFG taint chains being correctly built by the CPGParser for multi-step flows; regex patterns cover direct-access cases.
- Regex patterns added in v3 may introduce additional FPs for some edge cases (e.g., `os.system(variable)` patterns may flag non-user-controlled variables). LLM classification (disabled during benchmark) would filter these at runtime.
- CWE-94 (Code Injection) precision (96.08%) is the highest and must be preserved; the `re.compile` suppressor for CODE_INJECTION was left intact.
- Memory profiling and FP/KLOC are not yet recorded.
- Baseline tool comparisons (CodeQL, Semgrep, Snyk) are not yet recorded.
- Statistical significance tests are not yet complete.
- Patch validation is not yet complete.
- CWE-918 SSRF precision was 100% (0 FP) at v2; v3 new patterns may reduce this slightly while improving recall from 14.95%.

## 8. Recommended Final Report Structure

Use this order in the final evaluation chapter:

1. Objective and research questions.
2. Dataset and scope.
3. Experimental protocol.
4. Tool configurations.
5. Benchmark results.
6. Statistical analysis.
7. Patch validation.
8. Independent validation plan.
9. Limitations and threats to validity.
10. Conclusion.

## 9. Minimum Evidence Checklist

Before claiming a benchmark result, ensure these artifacts exist:

- Benchmark run ID from MongoDB.
- Raw JSON result export.
- Git commit hash.
- Dataset manifest.
- Per-CWE TP/FP/FN/TN table.
- Precision, recall, F1 calculations.
- Runtime and memory logs.
- FP/KLOC calculation.
- Notes on excluded cases.
- Reproduction command.
- Reviewer/auditor instructions.

