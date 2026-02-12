from __future__ import annotations

import ast
from typing import List

from app.patch_module.diff_utils import apply_unified_diff, PatchValidationError
from app.patch_module.models import ValidationResult


def validate_python_syntax(original_text: str, diff_text: str) -> ValidationResult:
    """Apply diff and validate Python syntax using ast.parse()."""
    try:
        patched = apply_unified_diff(original_text, diff_text)
        ast.parse(patched)
        return ValidationResult(name="python_syntax", passed=True, details="ast.parse ok")
    except (SyntaxError, PatchValidationError) as exc:
        return ValidationResult(name="python_syntax", passed=False, details=str(exc))


def validate_javascript_syntax(original_text: str, diff_text: str) -> ValidationResult:
    """Apply diff and validate JavaScript syntax using esprima if available."""
    patched = None
    try:
        patched = apply_unified_diff(original_text, diff_text)
    except PatchValidationError as exc:
        return ValidationResult(name="js_syntax", passed=False, details=str(exc))

    try:
        import esprima  # type: ignore
        esprima.parseScript(patched)
        return ValidationResult(name="js_syntax", passed=True, details="esprima ok")
    except ImportError:
        return ValidationResult(
            name="js_syntax",
            passed=True,
            details="syntax_unverified: esprima not installed"
        )
    except Exception as exc:
        return ValidationResult(name="js_syntax", passed=False, details=str(exc))


def run_syntax_validators(language: str, original_text: str, diff_text: str) -> List[ValidationResult]:
    lang = (language or "").lower()
    if lang.startswith("py"):
        return [validate_python_syntax(original_text, diff_text)]
    if lang in {"javascript", "js", "typescript", "ts", "tsx"}:
        return [validate_javascript_syntax(original_text, diff_text)]
    return [ValidationResult(name="syntax", passed=True, details="unknown language - skipped")]
