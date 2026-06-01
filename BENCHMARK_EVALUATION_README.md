# VULCAN Benchmark Evaluation Draft

This document is a partially filled evaluation template for VULCAN. It includes the benchmark results currently available from the CodeQL corpus evaluation and leaves explicit placeholders for baseline tools, statistical testing, patch validation, memory profiling, and third-party audit evidence.

## 1. Current Benchmark Summary

Current evaluated system:

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

Latest measured six-family result:

```text
Total scored outcomes: 3,649
TP: 634
FP: 50
FN: 2,964
TN: 1
Precision: 92.69%
Recall: 17.62%
F1: 29.61%
```

Previous dashboard baseline before recall improvements:

```text
TP: 469
FP: 38
FN: 3,350
Total cases: 3,857
Precision: 92.5%
Recall: 12.3%
F1: 21.7%
Runtime: 149.3 seconds
```

Observed improvement:

```text
Recall improved from 12.3% to 17.62%
F1 improved from 21.7% to 29.61%
Precision remained above the 90% target
```

## 2. Benchmark Results

### 2.1 VULCAN Per-CWE Results

| Tool | Dataset | CWE | TP | FP | FN | TN | Precision | Recall | F1 | FP/KLOC | Runtime | Peak Memory |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| VULCAN | CodeQL curated corpus | CWE-22 | 46 | 3 | 594 | TBD | 93.88% | 7.19% | 13.35% | TBD | TBD | TBD |
| VULCAN | CodeQL curated corpus | CWE-78 | 60 | 4 | 654 | TBD | 93.75% | 8.40% | 15.42% | TBD | TBD | TBD |
| VULCAN | CodeQL curated corpus | CWE-79 | 307 | 34 | 1,023 | TBD | 90.03% | 23.08% | 36.74% | TBD | TBD | TBD |
| VULCAN | CodeQL curated corpus | CWE-89 | 94 | 5 | 355 | TBD | 94.95% | 20.94% | 34.31% | TBD | TBD | TBD |
| VULCAN | CodeQL curated corpus | CWE-918 | 29 | 0 | 165 | TBD | 100.00% | 14.95% | 26.01% | TBD | TBD | TBD |
| VULCAN | CodeQL curated corpus | CWE-94 | 98 | 4 | 173 | TBD | 96.08% | 36.16% | 52.55% | TBD | TBD | TBD |
| VULCAN | CodeQL curated corpus | Overall | 634 | 50 | 2,964 | 1 | 92.69% | 17.62% | 29.61% | TBD | TBD | TBD |

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

- Recall remains modest at 17.62%, although improved from 12.3%.
- Some CodeQL expected rows represent fine-grained flow locations rather than one human-level vulnerability.
- Benchmark precision is strong, but broader real-world recall requires more framework-specific source/sink and interprocedural coverage.
- Memory profiling and FP/KLOC are not yet recorded.
- Baseline tool comparisons are not yet recorded.
- Statistical significance tests are not yet complete.
- Patch validation is not yet complete.

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

