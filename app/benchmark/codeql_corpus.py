from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


SUPPORTED_SOURCE_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx",
    ".html", ".htm", ".jinja", ".j2", ".ejs",
    ".hbs", ".handlebars", ".mustache", ".pug",
    ".json", ".yml", ".yaml", ".raml",
}

_LOCATION_RE = re.compile(r"^(?P<file>.+?):(?P<start_line>\d+):(?P<start_col>\d+):(?P<end_line>\d+):(?P<end_col>\d+)$")
_CWE_RE = re.compile(r"CWE-(?P<num>\d+)")
_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
_MISSING_ALERT_RE = re.compile(r"\$\s*MISSING\s*:\s*Alert\b", re.IGNORECASE)


@dataclass(frozen=True)
class ExpectedFinding:
    file: str
    start_line: int
    start_col: int
    end_line: int
    end_col: int
    message: str = ""
    related_locations: tuple[tuple[str, int, int, int, int], ...] = ()

    @property
    def key(self) -> tuple[str, int]:
        return (self.file.replace("\\", "/").lower(), self.start_line)

    @property
    def match_locations(self) -> tuple[tuple[str, int, int, int, int], ...]:
        primary = (self.file, self.start_line, self.start_col, self.end_line, self.end_col)
        if primary in self.related_locations:
            return self.related_locations
        return (primary,) + self.related_locations


@dataclass
class CodeQLCorpusCase:
    case_id: str
    name: str
    language: str
    cwe: str
    query: str
    fixture_dir: Path
    expected_file: Path
    qlref_file: Path | None
    source_files: list[str] = field(default_factory=list)
    expected_findings: list[ExpectedFinding] = field(default_factory=list)

    @property
    def has_positive_oracle(self) -> bool:
        return bool(self.expected_findings)


def normalize_cwe(value: str | None) -> str:
    if not value:
        return "UNKNOWN"
    match = _CWE_RE.search(value)
    if not match:
        return value.upper()
    return f"CWE-{int(match.group('num'))}"


def language_for_root(root: Path) -> str:
    name = root.name.lower()
    if "python" in name:
        return "python"
    if "javascript" in name or "js" in name:
        return "javascript"
    return "multi"


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_query_reference(qlref_file: Path | None) -> str:
    if not qlref_file or not qlref_file.exists():
        return ""
    for raw_line in qlref_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("query:"):
            return line.split(":", 1)[1].strip()
        if not line.startswith("#") and not line.startswith("postprocess:"):
            return line
    return ""


def parse_expected_file(expected_file: Path) -> list[ExpectedFinding]:
    """
    Parse CodeQL .expected output and return result rows from the #select table.

    CodeQL test output can also contain graph helper sections such as "edges" and
    "nodes". Those are not vulnerability findings, so when a #select section is
    present this parser only accepts rows from that section.
    """
    lines = expected_file.read_text(encoding="utf-8", errors="ignore").splitlines()
    has_select = any(line.strip() == "#select" for line in lines)
    if not has_select:
        return []
    in_select = not has_select
    findings: list[ExpectedFinding] = []
    seen: set[tuple[str, int, int, int, int]] = set()

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#"):
            in_select = line == "#select"
            continue
        if has_select and not in_select:
            continue
        if not line.startswith("|"):
            continue

        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if not cells:
            continue

        loc = _parse_location(cells[0])
        if not loc:
            continue
        related_locations = tuple(
            (
                parsed.file,
                parsed.start_line,
                parsed.start_col,
                parsed.end_line,
                parsed.end_col,
            )
            for parsed in (_parse_location(cell) for cell in cells)
            if parsed
        )

        key = (loc.file, loc.start_line, loc.start_col, loc.end_line, loc.end_col)
        if key in seen:
            continue
        seen.add(key)

        message = ""
        for cell in cells[1:]:
            if cell and not _parse_location(cell):
                message = cell
                break

        findings.append(ExpectedFinding(
            file=loc.file,
            start_line=loc.start_line,
            start_col=loc.start_col,
            end_line=loc.end_line,
            end_col=loc.end_col,
            message=message,
            related_locations=related_locations,
        ))

    return findings


def parse_missing_alert_comments(fixture_dir: Path, source_files: Iterable[str]) -> list[ExpectedFinding]:
    """Return source lines explicitly labeled by CodeQL tests as missing alerts."""
    findings: list[ExpectedFinding] = []
    for rel_file in source_files:
        path = fixture_dir / rel_file
        if not path.is_file():
            continue
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8", errors="ignore").splitlines(),
            start=1,
        ):
            if not _MISSING_ALERT_RE.search(line):
                continue
            findings.append(ExpectedFinding(
                file=rel_file.replace("\\", "/"),
                start_line=line_number,
                start_col=1,
                end_line=line_number,
                end_col=max(1, len(line)),
                message="MISSING: Alert",
            ))
    return findings


def _merge_expected_findings(findings: Iterable[ExpectedFinding]) -> list[ExpectedFinding]:
    merged: list[ExpectedFinding] = []
    seen: set[tuple[str, int, int, int, int]] = set()
    for finding in findings:
        key = (
            finding.file.replace("\\", "/").lower(),
            finding.start_line,
            finding.start_col,
            finding.end_line,
            finding.end_col,
        )
        if key in seen:
            continue
        seen.add(key)
        merged.append(finding)
    return merged


def discover_codeql_cases(roots: Iterable[Path]) -> list[CodeQLCorpusCase]:
    cases: list[CodeQLCorpusCase] = []
    for root in roots:
        root = root.resolve()
        if not root.exists():
            continue
        root_language = language_for_root(root)
        for expected_file in sorted(root.rglob("*.expected")):
            qlref_file = expected_file.with_suffix(".qlref")
            if not qlref_file.exists():
                qlref_file = None
            fixture_dir = expected_file.parent
            cwe = normalize_cwe(_cwe_from_path(expected_file))
            query = read_query_reference(qlref_file)
            source_files = _source_files_for_fixture(fixture_dir)
            language = root_language
            if language == "multi":
                language = _language_from_sources(source_files)
            rel_expected = expected_file.relative_to(root).as_posix()
            case_id = hashlib.sha1(f"{root.name}/{rel_expected}".encode("utf-8")).hexdigest()[:16]
            expected_findings = _merge_expected_findings(
                parse_expected_file(expected_file)
                + parse_missing_alert_comments(fixture_dir, source_files)
            )
            cases.append(CodeQLCorpusCase(
                case_id=case_id,
                name=f"{root.name}/{rel_expected}",
                language=language,
                cwe=cwe,
                query=query,
                fixture_dir=fixture_dir,
                expected_file=expected_file,
                qlref_file=qlref_file,
                source_files=source_files,
                expected_findings=expected_findings,
            ))
    return cases


def case_to_manifest_row(case: CodeQLCorpusCase) -> dict:
    source_hashes = {}
    for rel in case.source_files:
        path = case.fixture_dir / rel
        if path.is_file():
            source_hashes[rel] = file_sha256(path)

    return {
        "case_id": case.case_id,
        "name": case.name,
        "language": case.language,
        "cwe": case.cwe,
        "query": case.query,
        "fixture_dir": _portable_path(case.fixture_dir),
        "expected_file": _portable_path(case.expected_file),
        "qlref_file": _portable_path(case.qlref_file) if case.qlref_file else None,
        "source_files": case.source_files,
        "source_hashes": source_hashes,
        "expected_findings": [
            {
                "file": f.file,
                "start_line": f.start_line,
                "start_col": f.start_col,
                "end_line": f.end_line,
                "end_col": f.end_col,
                "message": f.message,
                "related_locations": [
                    {
                        "file": loc[0],
                        "start_line": loc[1],
                        "start_col": loc[2],
                        "end_line": loc[3],
                        "end_col": loc[4],
                    }
                    for loc in f.match_locations
                ],
            }
            for f in case.expected_findings
        ],
    }


def _portable_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except Exception:
        return str(path).replace("\\", "/")


def _parse_location(value: str) -> ExpectedFinding | None:
    match = _LOCATION_RE.match(value)
    if not match:
        return None
    return ExpectedFinding(
        file=match.group("file").replace("\\", "/"),
        start_line=int(match.group("start_line")),
        start_col=int(match.group("start_col")),
        end_line=int(match.group("end_line")),
        end_col=int(match.group("end_col")),
        related_locations=(),
    )


def _cwe_from_path(path: Path) -> str:
    for part in path.parts:
        if _CWE_RE.search(part):
            return part
        cve = _CVE_RE.search(part)
        if cve:
            return cve.group(0).upper()
    return ""


def _source_files_for_fixture(fixture_dir: Path) -> list[str]:
    files = []
    for path in sorted(fixture_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in SUPPORTED_SOURCE_SUFFIXES:
            continue
        if any(part in {"node_modules", "venv", ".venv", ".git", "__pycache__", ".vulcan_cache"} for part in path.parts):
            continue
        files.append(path.relative_to(fixture_dir).as_posix())
    return files


def _language_from_sources(source_files: list[str]) -> str:
    suffixes = {Path(path).suffix.lower() for path in source_files}
    if suffixes and suffixes <= {".py"}:
        return "python"
    if suffixes and suffixes <= {".js", ".jsx", ".ts", ".tsx"}:
        return "javascript"
    if ".py" in suffixes and not suffixes.intersection({".js", ".jsx", ".ts", ".tsx"}):
        return "python"
    if suffixes.intersection({".js", ".jsx", ".ts", ".tsx"}) and ".py" not in suffixes:
        return "javascript"
    return "multi"
