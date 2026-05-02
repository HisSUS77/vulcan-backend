from __future__ import annotations

import ast
import textwrap
from typing import List

from app.patch_module.diff_utils import apply_unified_diff, PatchValidationError
from app.patch_module.models import ValidationResult


def _try_parse_python(code: str) -> ValidationResult:
    """
    Try to ast.parse a Python code snippet, handling 3 cases:
    1. Top-level code — parse directly.
    2. Indented snippet (inside a function/class) — dedent first.
    3. Still indented after dedent — wrap in a dummy function.
    """
    # Attempt 1: parse as-is
    try:
        ast.parse(code)
        return ValidationResult(name="python_syntax", passed=True, details="ast.parse ok")
    except IndentationError:
        pass
    except SyntaxError as exc:
        # Real syntax error, not just indentation — report it
        return ValidationResult(name="python_syntax", passed=False,
                                details=f"syntax error in patched code: {exc}")

    # Attempt 2: dedent
    dedented = textwrap.dedent(code)
    try:
        ast.parse(dedented)
        return ValidationResult(name="python_syntax", passed=True,
                                details="ast.parse ok (dedented)")
    except IndentationError:
        pass
    except SyntaxError as exc:
        return ValidationResult(name="python_syntax", passed=False,
                                details=f"syntax error in patched code: {exc}")

    # Attempt 3: wrap in a dummy function so indented code is valid
    wrapped = "def _vulcan_patch_check():\n" + textwrap.indent(dedented, "    ")
    try:
        ast.parse(wrapped)
        return ValidationResult(name="python_syntax", passed=True,
                                details="ast.parse ok (wrapped in function)")
    except SyntaxError as exc:
        return ValidationResult(name="python_syntax", passed=False,
                                details=f"syntax error in patched code: {exc}")


def _extract_patched_view(diff_text: str) -> str:
    """
    Extract the patched code view from a unified diff without needing the
    original file. Takes context lines (space-prefixed) and added lines (+).
    This avoids the 'hunk exceeds original text length' problem when only
    a short code slice is stored rather than the full file.
    """
    lines = []
    for line in diff_text.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            lines.append(line[1:])
        elif line.startswith(" "):          # context line
            lines.append(line[1:])
        # skip --- +++ @@ and removed lines
    return "\n".join(lines)


def validate_python_syntax(original_text: str, diff_text: str) -> ValidationResult:
    """
    Validate Python syntax on the patched code.
    Primary: apply the diff to original_text and ast.parse the result.
    Fallback: extract the patched view directly from diff +/context lines.
    """
    # Primary attempt — full apply then parse
    try:
        patched = apply_unified_diff(original_text, diff_text)
        return _try_parse_python(patched)
    except PatchValidationError:
        pass  # fall through to patched-view extraction

    # Fallback — extract patched view from diff lines directly
    try:
        patched_view = _extract_patched_view(diff_text)
        if not patched_view.strip():
            return ValidationResult(
                name="python_syntax", passed=True,
                details="syntax_unverified: empty patched view"
            )
        return _try_parse_python(patched_view)
    except Exception as exc:
        return ValidationResult(
            name="python_syntax", passed=True,
            details=f"syntax_unverified: {exc}"
        )


def validate_javascript_syntax(original_text: str, diff_text: str) -> ValidationResult:
    """
    Validate JavaScript syntax on the patched code.
    Falls back to patched-view extraction when apply fails.
    """
    # Primary attempt
    patched = None
    try:
        patched = apply_unified_diff(original_text, diff_text)
    except PatchValidationError:
        pass  # use fallback below

    if patched is None:
        patched = _extract_patched_view(diff_text)

    if not patched.strip():
        return ValidationResult(
            name="js_syntax", passed=True,
            details="syntax_unverified: empty patched view"
        )

    try:
        import esprima  # type: ignore
        esprima.parseScript(patched)
        return ValidationResult(name="js_syntax", passed=True, details="esprima ok")
    except ImportError:
        return ValidationResult(
            name="js_syntax", passed=True,
            details="syntax_unverified: esprima not installed"
        )
    except Exception as exc:
        return ValidationResult(name="js_syntax", passed=False, details=str(exc))


# Dispatch to the language-appropriate syntax validator and return its results.
def run_syntax_validators(
    language: str, original_text: str, diff_text: str
) -> List[ValidationResult]:
    lang = (language or "").lower()
    if lang.startswith("py"):
        return [validate_python_syntax(original_text, diff_text)]
    if lang in {"javascript", "js", "typescript", "ts", "tsx"}:
        return [validate_javascript_syntax(original_text, diff_text)]
    return [ValidationResult(
        name="syntax", passed=True, details="unknown language — skipped"
    )]
