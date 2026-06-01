# Vulcan Benchmarking Methodology

## Benchmark Tiers

Vulcan keeps three benchmark tiers separate:

1. `synthetic`: small hand-written smoke tests used for fast regression checks.
2. `codeql-corpus`: checked-in CodeQL security fixtures with `.qlref` and `.expected` files used as the independent oracle.
3. `field`: real scan findings reviewed by the AI/human oracle. This measures precision only unless clean negatives are also sampled.

Only `codeql-corpus` should be presented as the primary reproducible benchmark.

## CodeQL Corpus Curation

The corpus is curated directly from:

- `Security-python`
- `Security_ javascript`

Each benchmark case is one CodeQL `.expected` file. The paired `.qlref` identifies the CodeQL query, the fixture directory supplies the source files, and the `.expected` `#select` rows define vulnerable source/sink locations.

Run the full manifest:

```powershell
python scripts/curate_codeql_benchmark.py
```

Run the Vulcan-supported benchmark scope:

```powershell
python scripts/curate_codeql_benchmark.py --supported-only --output benchmarks/codeql_supported_manifest.json
```

This writes `benchmarks/codeql_manifest.json` with:

- deterministic `case_id`
- language, CWE, query reference, fixture path
- source file list and SHA-256 hashes
- expected finding file/line/column locations

That manifest is what an external reviewer can diff, audit, and regenerate.

Unsupported CodeQL cases are not deleted from the repository. In the supported
manifest they are listed under `excluded_cases` with a reason, so the benchmark
scope remains transparent.

## Scoring

`POST /api/v1/benchmark/run-codeql-corpus` runs Vulcan over each fixture directory with exploit generation disabled. By default it uses `supported_only: true`, which excludes CodeQL CWEs outside Vulcan's stated benchmark scope. Set `supported_only: false` to audit against the full CodeQL corpus.

Scoring is finding-level:

- `TP`: CodeQL expected finding matched by a Vulcan finding for the same normalized CWE and same file within the configured line tolerance.
- `FN`: CodeQL expected finding not matched.
- `FP`: Vulcan finding for the same CWE with no matching CodeQL expected location.
- `TN`: empty CodeQL oracle and no Vulcan finding for that CWE.

Default line tolerance is `2` because semantic graph tools may report the enclosing sink expression or call site rather than CodeQL's exact token span. For strict audits, run with `line_tolerance: 0`.

## Recommended Reporting

Report results by:

- overall precision, recall, F1
- per-CWE precision, recall, F1
- language split
- strict line match and relaxed line match
- static-only and LLM-enabled modes separately

Do not mix synthetic, CodeQL corpus, and field results into one headline score.
