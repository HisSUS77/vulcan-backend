# VULCAN Benchmark Evaluation Report Checklist

Use this README as the structure for the final benchmarking and evaluation document. Each section should include enough raw evidence that an independent reviewer can reproduce or challenge the claims.

## 1. Benchmark Results

Report per-tool and per-family performance.

Include:

- Tool name and version: VULCAN, CodeQL, Semgrep, Snyk, etc.
- Dataset/corpus name: CodeQL security fixtures, curated supported corpus, field scans.
- CWE family: CWE-89, CWE-78, CWE-79, CWE-22, CWE-918, CWE-94, etc.
- Accuracy.
- Precision.
- Recall.
- F1 score.
- TP, FP, FN, TN counts.
- False positives per 1 KLOC.
- Runtime per benchmark run.
- Peak memory usage.
- Number of files scanned.
- Number of lines of code scanned.
- Static-only vs LLM-enabled mode.

Suggested table:

```text
Tool | Dataset | CWE | TP | FP | FN | TN | Precision | Recall | F1 | FP/KLOC | Runtime | Peak Memory
```

## 2. Statistical Analysis

Show whether VULCAN's results are meaningfully different from baseline tools.

Include:

- Raw TP, FP, FN, TN counts per tool.
- Per-CWE paired comparison against baseline tools.
- McNemar test for paired classification disagreement.
- Paired t-test or Wilcoxon signed-rank test for per-case/per-CWE metric differences.
- Confidence intervals where possible.
- Significance threshold, for example `p < 0.05`.
- Explanation of what each test proves and does not prove.

Suggested table:

```text
Comparison | Dataset | Metric | Test | Statistic | p-value | Significant? | Interpretation
```

## 3. Experimental Protocol

Make the experiment reproducible.

Include:

- VULCAN commit hash.
- Baseline tool versions and commit hashes.
- Query/rule-set versions.
- Dataset commit hashes.
- Included CWE families.
- Excluded CWE families and reason for exclusion.
- CVE IDs if real-world vulnerable projects are used.
- Annotation methodology.
- Ground-truth source, for example CodeQL `.expected` files or manual review.
- Line matching tolerance.
- Deduplication rules.
- Safe-pattern suppression policy.
- Hardware specs:
  - CPU
  - RAM
  - GPU, if used
  - Disk
  - OS
- Software specs:
  - Python version
  - Node version
  - Database version
  - Docker version, if used
- Runtime configuration:
  - Static-only or LLM-enabled
  - Max path length
  - Max paths per rule
  - Max candidate paths
  - Enabled/disabled exploit generation

Suggested table:

```text
Component | Version / Commit | Configuration | Notes
```

## 4. Patch Validation Report

Evaluate whether generated patches actually fix vulnerabilities without breaking the application.

Include:

- Number of vulnerabilities selected for patching.
- Number of patches generated.
- Patch success rate.
- Patch application failure rate.
- Test-suite pass/fail before patch.
- Test-suite pass/fail after patch.
- Security regression result: whether VULCAN still detects the same issue after patching.
- Functional regression result: whether existing app tests still pass.
- Manual review outcome.
- Time taken to generate and validate patches.

Suggested table:

```text
Finding ID | CWE | Patch Applied? | Security Re-scan Passed? | Tests Passed? | Manual Verdict | Notes
```

Key metrics:

```text
Patch Success Rate = successful patches / attempted patches
Security Fix Rate = findings removed after patch / patched findings
Regression Rate = patches causing test failure / successful patches
```

## 5. Independent Validation

Prepare materials for third-party scrutiny.

Include:

- Source code repository access.
- Exact commit hash used for evaluation.
- Benchmark dataset or sample data.
- Curated manifest of included/excluded benchmark cases.
- Benchmark runner instructions.
- Environment setup instructions.
- Expected output files.
- Raw benchmark result exports.
- Scripts used to calculate metrics.
- Any manual annotation sheets.
- Private repository access instructions, if real private repos are part of evaluation.
- Auditor contact/access procedure.
- Known limitations and threats to validity.

Suggested auditor package:

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

## 6. Recommended Final Report Structure

Use this order in the final document:

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

## 7. Minimum Evidence Checklist

Before claiming a benchmark result, ensure these artifacts exist:

- Benchmark run ID from MongoDB.
- Raw JSON result export.
- Git commit hash.
- Dataset manifest.
- Per-CWE TP/FP/FN/TN table.
- Precision, recall, F1 calculations.
- Runtime and memory logs.
- Notes on excluded cases.
- Reproduction command.
- Reviewer/auditor instructions.

