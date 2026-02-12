from __future__ import annotations

from typing import List

from app.patch_module.models import ValidationResult, VulnerabilityContext
from app.patch_module.diff_utils import parse_unified_diff, apply_unified_diff, PatchValidationError
from app.patch_module.syntax_validator import run_syntax_validators
from app.patch_module.semantic_validator import validate_semantics


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

        try:
            patched_text = apply_unified_diff(original_text, unified_diff)
        except PatchValidationError as exc:
            validations.append(ValidationResult(name="apply_diff", passed=False, details=str(exc)))
            return validations

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
        return validations
