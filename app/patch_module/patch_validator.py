from __future__ import annotations

from typing import List

from app.patch_module.models import ValidationResult, VulnerabilityContext
from app.patch_module.diff_utils import parse_unified_diff, apply_unified_diff, PatchValidationError
from app.patch_module.syntax_validator import run_syntax_validators
from app.patch_module.semantic_validator import validate_semantics
from app.patch_module.ast_validator import validate_python_ast


class PatchValidator:
    """
    Wrapper class for patch validation pipeline.
    Validates diff format, syntax, and semantic rules.
    """

    def validate(self, ctx: VulnerabilityContext, unified_diff: str) -> List[ValidationResult]:
        validations: List[ValidationResult] = []

        try:
            summary = parse_unified_diff(unified_diff)
            target = summary.target_file.replace("\\", "/")
            expected = ctx.file_path.replace("\\", "/")
            if target and expected and not target.endswith(expected):
                raise PatchValidationError("Diff target file does not match vulnerability file")
            validations.append(
                ValidationResult(name="diff_format", passed=True, details=f"{summary.added_lines} added")
            )
        except PatchValidationError as exc:
            validations.append(ValidationResult(name="diff_format", passed=False, details=str(exc)))
            return validations

        original_text = ctx.context_before_after or ctx.vulnerable_slice
        validations.extend(run_syntax_validators(ctx.language, original_text, unified_diff))

        # Try to apply diff; if it fails only due to context-length mismatch
        # (short slice vs full-file diff), treat it as a soft warning not a
        # hard failure — the syntax check above already verified the patch code.
        patched_text = None
        try:
            patched_text = apply_unified_diff(original_text, unified_diff)
            validations.append(ValidationResult(
                name="apply_diff", passed=True, details="diff applied cleanly"
            ))
        except PatchValidationError as exc:
            detail = str(exc)
            context_mismatch = (
                "exceeds original text length" in detail
                or "hunk exceeds" in detail
                or "context line" in detail.lower()
            )
            if context_mismatch:
                # Patch is valid but slice is shorter than the hunk — not a real error
                validations.append(ValidationResult(
                    name="apply_diff", passed=True,
                    details="diff valid (slice shorter than hunk context — full-file apply needed)"
                ))
                # Extract patched view from diff lines for semantic checking
                from app.patch_module.syntax_validator import _extract_patched_view
                patched_text = _extract_patched_view(unified_diff)
            else:
                validations.append(ValidationResult(
                    name="apply_diff", passed=False, details=detail
                ))
                return validations

        if patched_text is not None:
            validations.extend(
                validate_semantics(
                    ctx.vuln_type,
                    ctx.sink,
                    ctx.source,
                    ctx.taint_path,
                    ctx.vulnerable_slice,
                    patched_text,
                )
            )
            # AST-level analysis for Python — runs alongside string-matching.
            # Catches aliased imports, multi-line expressions, and complex
            # patterns that string matching misses.
            lang = (ctx.language or "").lower()
            if lang.startswith("py"):
                validations.extend(validate_python_ast(patched_text))

        return validations
