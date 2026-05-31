from pathlib import Path

from app.benchmark.codeql_corpus import (
    discover_codeql_cases,
    normalize_cwe,
    parse_expected_file,
    parse_missing_alert_comments,
    read_query_reference,
)
from app.benchmark.scope import (
    canonical_benchmark_cwe,
    is_supported_codeql_case,
    supported_cwes_from_queries,
)


ROOT = Path(__file__).resolve().parents[2]


def test_normalize_cwe_strips_leading_zeroes():
    assert normalize_cwe("CWE-089-SqlInjection") == "CWE-89"
    assert normalize_cwe("Security/CWE-078/CommandInjection.ql") == "CWE-78"


def test_parse_expected_file_uses_select_rows_not_graph_edges():
    expected = ROOT / "Security-python" / "CWE-089-SqlInjection" / "SqlInjection.expected"
    findings = parse_expected_file(expected)

    assert findings
    assert {finding.file for finding in findings} == {"sql_injection.py", "sqlalchemy_textclause.py"}
    assert ("sql_injection.py", 21) in {finding.key for finding in findings}


def test_parse_missing_alert_comments_uses_author_labeled_vulnerable_lines():
    fixture = ROOT / "Security_ javascript" / "CWE-094" / "CodeInjection"
    findings = parse_missing_alert_comments(fixture, ["lib/index.js"])

    assert ("lib/index.js", 51) in {finding.key for finding in findings}


def test_read_query_reference_supports_plain_and_keyed_qlref():
    plain = ROOT / "Security-python" / "CWE-089-SqlInjection" / "SqlInjection.qlref"
    keyed = ROOT / "Security_ javascript" / "CWE-078" / "CommandInjection" / "CommandInjection.qlref"

    assert read_query_reference(plain) == "Security/CWE-089/SqlInjection.ql"
    assert read_query_reference(keyed) == "Security/CWE-078/CommandInjection.ql"


def test_discover_codeql_cases_creates_deterministic_case_metadata():
    root = ROOT / "Security-python" / "CWE-089-SqlInjection"
    cases = discover_codeql_cases([root])

    case = next(c for c in cases if c.expected_file.name == "SqlInjection.expected")
    assert case.cwe == "CWE-89"
    assert case.language == "python"
    assert case.case_id
    assert "sql_injection.py" in case.source_files
    assert len(case.expected_findings) >= 1


def test_supported_scope_includes_aliases_and_excludes_unclaimed_cwes():
    supported = supported_cwes_from_queries(ROOT / "queries" / "queries.json")

    assert is_supported_codeql_case("CWE-89", supported)
    assert is_supported_codeql_case("CWE-94", supported)  # CodeQL code injection alias
    assert is_supported_codeql_case("CWE-730", supported)  # CodeQL ReDoS alias
    assert not is_supported_codeql_case("CWE-1275", supported)
    assert canonical_benchmark_cwe("CWE-94") == "CWE-95"
