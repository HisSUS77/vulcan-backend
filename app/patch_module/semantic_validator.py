from __future__ import annotations

from typing import List

from app.patch_module.models import ValidationResult


def validate_semantics(
    vuln_type: str,
    sink: str | None,
    source: str | None,
    taint_path: list | str | None,
    original_slice: str,
    patched_slice: str,
) -> List[ValidationResult]:
    key = (vuln_type or "").lower()
    if "sqli" in key or "sql" in key:
        return [_validate_sqli(patched_slice)]
    if "xss" in key:
        return [_validate_xss(patched_slice)]
    if "command" in key:
        return [_validate_command_injection(patched_slice)]
    return [ValidationResult(name="semantic", passed=True, details="no specific semantic rule")]


def _validate_sqli(patched_slice: str) -> ValidationResult:
    text = patched_slice.lower()
    has_execute = "execute(" in text or "query(" in text
    has_params = ("execute(" in text and "," in text) or "%s" in text or "?" in text
    fstring = "f\"" in text or "f'" in text
    concat = "+" in text and "select" in text
    if has_execute and has_params and not fstring and not concat:
        return ValidationResult(name="semantic_sqli", passed=True, details="parameterized query detected")
    return ValidationResult(name="semantic_sqli", passed=False, details="SQLi fix not detected")


def _validate_xss(patched_slice: str) -> ValidationResult:
    text = patched_slice.lower()
    unsafe_inner = "innerhtml" in text
    has_escape = "escape(" in text or "html.escape" in text or "dompurify" in text or "textcontent" in text
    if (not unsafe_inner and has_escape) or "textcontent" in text:
        return ValidationResult(name="semantic_xss", passed=True, details="output escaping/safe rendering detected")
    return ValidationResult(name="semantic_xss", passed=False, details="XSS fix not detected")


def _validate_command_injection(patched_slice: str) -> ValidationResult:
    text = patched_slice.lower()
    bad = "os.system" in text or "child_process.exec" in text or "shell=true" in text
    safe = "subprocess.run" in text and "shell=false" in text or "execfile" in text or "execfile(" in text
    safe_js = "execfile" in text or "spawn(" in text or "execfile(" in text
    if not bad and (safe or safe_js):
        return ValidationResult(name="semantic_command_injection", passed=True, details="safe subprocess/execfile detected")
    return ValidationResult(name="semantic_command_injection", passed=False, details="command injection fix not detected")
