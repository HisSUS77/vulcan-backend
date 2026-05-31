from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.benchmark.codeql_corpus import case_to_manifest_row, discover_codeql_cases
from app.benchmark.scope import is_supported_codeql_case, supported_cwes_from_queries


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a deterministic manifest from checked-in CodeQL security fixtures."
    )
    parser.add_argument(
        "--root",
        action="append",
        default=None,
        help="Corpus root to scan. Can be passed multiple times.",
    )
    parser.add_argument(
        "--output",
        default="benchmarks/codeql_manifest.json",
        help="Path for the generated JSON manifest.",
    )
    parser.add_argument(
        "--supported-only",
        action="store_true",
        help="Only include CodeQL cases whose CWE is in Vulcan's supported benchmark scope.",
    )
    args = parser.parse_args()

    workspace = Path.cwd()
    roots = [workspace / r for r in (args.root or ["Security-python", "Security_ javascript"])]
    cases = discover_codeql_cases(roots)
    supported_cwes = supported_cwes_from_queries(workspace / "queries" / "queries.json")
    excluded = []
    if args.supported_only:
        kept = []
        for case in cases:
            if is_supported_codeql_case(case.cwe, supported_cwes):
                kept.append(case)
            else:
                excluded.append({
                    "case_id": case.case_id,
                    "name": case.name,
                    "language": case.language,
                    "cwe": case.cwe,
                    "query": case.query,
                    "reason": "No Vulcan benchmark-scoped query for this CWE",
                })
        cases = kept
    rows = [case_to_manifest_row(case) for case in cases]

    output = workspace / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({
        "schema": "vulcan-codeql-corpus-manifest/v1",
        "case_count": len(rows),
        "positive_finding_count": sum(len(row["expected_findings"]) for row in rows),
        "scope": "supported" if args.supported_only else "all",
        "supported_cwes": sorted(supported_cwes),
        "excluded_case_count": len(excluded),
        "excluded_cases": excluded,
        "roots": [_portable_path(root) for root in roots],
        "cases": rows,
    }, indent=2), encoding="utf-8")

    by_language = {}
    by_cwe = {}
    for row in rows:
        by_language[row["language"]] = by_language.get(row["language"], 0) + 1
        by_cwe[row["cwe"]] = by_cwe.get(row["cwe"], 0) + 1

    print(f"Wrote {len(rows)} cases to {output}")
    if excluded:
        print(f"Excluded unsupported cases: {len(excluded)}")
    print(f"Expected findings: {sum(len(row['expected_findings']) for row in rows)}")
    print(f"Languages: {dict(sorted(by_language.items()))}")
    print(f"CWEs: {dict(sorted(by_cwe.items()))}")
    return 0


def _portable_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except Exception:
        return str(path).replace("\\", "/")


if __name__ == "__main__":
    raise SystemExit(main())
