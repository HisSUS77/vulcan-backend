from __future__ import annotations

import json
from pathlib import Path

from app.benchmark.codeql_corpus import normalize_cwe


BENCHMARK_CWE_ALIASES = {
    # CodeQL and Vulcan sometimes use sibling CWE IDs for the same benchmarked
    # weakness family. These aliases are benchmark-scoping only; they do not
    # rewrite scanner findings.
    "CWE-73": "CWE-22",       # External path control -> path traversal family
    "CWE-74": "CWE-1336",     # Injection -> template injection corpus
    "CWE-94": "CWE-95",       # Code construction/eval injection family
    "CWE-338": "CWE-330",     # Weak random generation family
    "CWE-400": "CWE-1333",    # ReDoS/resource exhaustion corpus
    "CWE-730": "CWE-1333",    # OWASP/CodeQL ReDoS tests
}


def supported_cwes_from_queries(queries_path: Path | None = None) -> set[str]:
    project_root = Path(__file__).resolve().parents[2]
    queries_path = queries_path or project_root / "queries" / "queries.json"
    data = json.loads(queries_path.read_text(encoding="utf-8"))

    supported = {
        normalize_cwe(rule.get("cwe"))
        for rule in data.values()
        if rule.get("cwe")
    }
    supported.discard("UNKNOWN")

    for alias, canonical in BENCHMARK_CWE_ALIASES.items():
        if canonical in supported:
            supported.add(alias)

    return supported


def is_supported_codeql_case(cwe: str, supported_cwes: set[str]) -> bool:
    cwe = normalize_cwe(cwe)
    return cwe in supported_cwes


def canonical_benchmark_cwe(cwe: str | None) -> str:
    normalized = normalize_cwe(cwe)
    return BENCHMARK_CWE_ALIASES.get(normalized, normalized)
