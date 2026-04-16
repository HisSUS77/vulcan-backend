from __future__ import annotations

import logging
from datetime import datetime
from typing import List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.exceptions import ValidationException, ResourceNotFoundException
from app.patch_module.models import (
    VulnerabilityContext,
    ValidationResult,
    PatchGenerateResponse,
    PatchValidateResponse,
    PatchApplyResponse,
    PatchReviewResponse,
    PatchHistoryItem,
)
from app.patch_module.prompt_builder import PromptBuilder
from app.patch_module.patch_llm_service import PatchLLMService
from app.patch_module.patch_validator import PatchValidator
from app.patch_module.patch_repository import PatchRepository
from app.patch_module.guards import enforce_rate_limit, enforce_slice_length, reject_secrets

logger = logging.getLogger(__name__)


class PatchOrchestrator:
    def __init__(self, db: AsyncIOMotorDatabase):
        # DB + helpers used across generate/validate/apply flows.
        self.db = db
        self.repo = PatchRepository(db)
        self.llm = PatchLLMService()
        self.validator = PatchValidator()

    async def generate(
        self,
        user_id: str,
        vulnerability_id: Optional[str],
        context: Optional[VulnerabilityContext],
    ) -> PatchGenerateResponse:
        # Load vulnerability context (from request or DB by vulnerability_id).
        ctx = context or await self._load_context(user_id, vulnerability_id)
        if ctx is None:
            raise ResourceNotFoundException("Vulnerability context not found")

        # Guardrails: rate limit, max slice size, reject secrets in prompt.
        await enforce_rate_limit(self.db, user_id)
        enforce_slice_length(ctx.vulnerable_slice)
        reject_secrets(ctx.vulnerable_slice)

        # Build a strict prompt and ask LLM for a unified diff patch.
        original_prompt = PromptBuilder.build_prompt(
            language=ctx.language,
            vuln_type=ctx.vuln_type,
            cwe=ctx.cwe,
            owasp=ctx.owasp,
            vulnerable_slice=ctx.vulnerable_slice,
            context_before_after=ctx.context_before_after,
            taint_path=ctx.taint_path,
            sink=ctx.sink,
            source=ctx.source,
            file_path=ctx.file_path,
        )

        # Build industrial 4-phase adversarial CoT prompt for first attempt.
        industrial_cot_prompt = PromptBuilder.build_industrial_cot_prompt(
            language=ctx.language,
            vuln_type=ctx.vuln_type,
            cwe=ctx.cwe,
            owasp=ctx.owasp,
            vulnerable_slice=ctx.vulnerable_slice,
            context_before_after=ctx.context_before_after,
            taint_path=ctx.taint_path,
            sink=ctx.sink,
            source=ctx.source,
            file_path=ctx.file_path,
        )

        # ── Self-critique retry loop ───────────────────────────────────────────
        # Attempt 0: Industrial CoT (4-phase analysis → PATCH_SPEC → diff).
        # Attempts 1-2: critique prompt — model already has failure context.
        # We keep the best attempt (highest confidence), not just the last.
        _MAX_ATTEMPTS = 3
        _CONFIDENCE_GOAL = 0.80

        best_diff: str = ""
        best_confidence: float = 0.0
        best_validations: List[ValidationResult] = []
        current_prompt = original_prompt
        generation_attempts = 0

        for attempt in range(_MAX_ATTEMPTS):
            generation_attempts = attempt + 1
            if attempt == 0:
                # Industrial CoT: 4-phase adversarial analysis → PATCH_SPEC → diff.
                unified_diff = await self.llm.generate_patch_with_industrial_cot(
                    industrial_cot_prompt, original_prompt
                )
            else:
                # Critique retry: current_prompt already contains failure context.
                unified_diff = await self.llm.generate_patch(current_prompt)
            validations = self._run_validations(ctx, unified_diff)
            confidence = self._compute_confidence(unified_diff, validations)

            if confidence > best_confidence:
                best_diff = unified_diff
                best_confidence = confidence
                best_validations = validations

            if best_confidence >= _CONFIDENCE_GOAL:
                break  # Good enough — stop here

            if attempt < _MAX_ATTEMPTS - 1:
                failures = [v for v in validations if not v.passed]
                if not failures:
                    break  # All passed but below goal — nothing to critique
                logger.info(
                    "Patch attempt %d confidence=%.0f%% — critiquing %d failure(s)",
                    attempt + 1, confidence * 100, len(failures),
                )
                current_prompt = PromptBuilder.build_critique_prompt(
                    original_prompt, unified_diff, failures
                )

        unified_diff = best_diff
        validations = best_validations
        confidence = best_confidence
        # ──────────────────────────────────────────────────────────────────────

        status = "generated" if all(v.passed for v in validations) else "rejected"

        # Compute multi-dimensional score breakdown and explanation.
        score_breakdown = self._compute_score_breakdown(validations, confidence, generation_attempts)
        explanation = self._build_explanation(validations, ctx)

        # Count existing patches for this vuln to compute version number.
        existing = await self.repo.list_by_vulnerability_ids([ctx.vulnerability_id] if ctx.vulnerability_id else [])
        version = len(existing) + 1

        # Persist patch record in DB.
        patch_id = await self.repo.create_patch({
            "patch_id": None,
            "vulnerability_id": ctx.vulnerability_id,
            "user_id": user_id,
            "repo_id": None,
            "file_path": ctx.file_path,
            "language": ctx.language,
            "vuln_type": ctx.vuln_type,
            "cwe": ctx.cwe,
            "owasp": ctx.owasp,
            "source": ctx.source,
            "sink": ctx.sink,
            "taint_path": ctx.taint_path,
            "vulnerable_slice": ctx.vulnerable_slice,
            "context_before_after": ctx.context_before_after,
            "unified_diff": unified_diff,
            "explanation": explanation,
            "confidence": confidence,
            "score_breakdown": score_breakdown,
            "generation_attempts": generation_attempts,
            "validations": [v.model_dump() for v in validations],
            "status": status,
            "review_status": "pending_review",
            "version": version,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        })
        # Sync patch status into the scan summary for UI consumption.
        await self._sync_patch_to_scan(ctx.vulnerability_id, patch_id, status, confidence, validations)

        return PatchGenerateResponse(
            patch_id=patch_id,
            unified_diff=unified_diff,
            explanation=explanation,
            confidence=confidence,
            score_breakdown=score_breakdown,
            generation_attempts=generation_attempts,
            validations=validations,
            status=status,
            review_status="pending_review",
            cwe=ctx.cwe,
            owasp=ctx.owasp,
            version=version,
        )

    async def validate(self, patch_id: str) -> PatchValidateResponse:
        # Re-run validators on an existing patch and update its status.
        patch = await self.repo.get_patch(patch_id)
        if not patch:
            raise ResourceNotFoundException("Patch not found")
        ctx = VulnerabilityContext(
            vulnerability_id=patch.get("vulnerability_id"),
            file_path=patch.get("file_path", ""),
            language=patch.get("language", ""),
            vuln_type=patch.get("vuln_type", ""),
            cwe=patch.get("cwe"),
            owasp=patch.get("owasp"),
            vulnerable_slice=patch.get("vulnerable_slice", ""),
            context_before_after=patch.get("context_before_after"),
            taint_path=patch.get("taint_path"),
            sink=patch.get("sink"),
            source=patch.get("source"),
        )

        unified_diff = patch.get("unified_diff", "")
        validations = self._run_validations(ctx, unified_diff)
        status = "validated" if all(v.passed for v in validations) else "rejected"
        # Persist updated validation results.
        await self.repo.update_patch(patch_id, {
            "validations": [v.model_dump() for v in validations],
            "status": status,
        })
        # Sync summary in scans collection for UI.
        await self._sync_patch_to_scan(ctx.vulnerability_id, patch_id, status, patch.get("confidence"), validations)
        return PatchValidateResponse(patch_id=patch_id, validations=validations, status=status)

    async def apply(self, patch_id: str, user_id: str, repo_id: Optional[str]) -> PatchApplyResponse:
        # Create a "pending apply" record; actual repo changes are external.
        patch = await self.repo.get_patch(patch_id)
        if not patch:
            raise ResourceNotFoundException("Patch not found")

        pending_apply_id = await self.repo.create_pending_apply(patch_id, user_id, repo_id)
        branch = f"vulcan/patch-{patch_id[:8]}"
        # Mark patch as pending apply and sync to scan.
        await self.repo.update_patch(patch_id, {"status": "applied_pending"})
        patch_validations = patch.get("validations") or []
        validation_objs = [ValidationResult(**v) if isinstance(v, dict) else v for v in patch_validations]
        await self._sync_patch_to_scan(
            patch.get("vulnerability_id"),
            patch_id,
            "applied_pending",
            patch.get("confidence"),
            validation_objs,
        )

        return PatchApplyResponse(
            patch_id=patch_id,
            status="applied_pending",
            pending_apply_id=pending_apply_id,
            branch_suggestion=branch,
            instructions="Create a branch, apply the patch file, run tests, then open a PR.",
        )

    async def export(self, patch_id: str) -> str:
        # Return the unified diff for download/export.
        patch = await self.repo.get_patch(patch_id)
        if not patch:
            raise ResourceNotFoundException("Patch not found")
        return patch.get("unified_diff", "")

    async def approve(self, patch_id: str, user_id: str) -> PatchReviewResponse:
        """FR-M6.10: Approve a generated patch for deployment."""
        patch = await self.repo.get_patch(patch_id)
        if not patch:
            raise ResourceNotFoundException("Patch not found")
        await self.repo.update_patch(patch_id, {
            "review_status": "approved",
            "reviewed_by": user_id,
        })
        return PatchReviewResponse(
            patch_id=patch_id,
            status=patch.get("status", ""),
            review_status="approved",
        )

    async def reject(self, patch_id: str, user_id: str) -> PatchReviewResponse:
        """FR-M6.10: Reject a generated patch before deployment."""
        patch = await self.repo.get_patch(patch_id)
        if not patch:
            raise ResourceNotFoundException("Patch not found")
        await self.repo.update_patch(patch_id, {
            "review_status": "rejected",
            "reviewed_by": user_id,
        })
        return PatchReviewResponse(
            patch_id=patch_id,
            status=patch.get("status", ""),
            review_status="rejected",
        )

    async def list_for_vulnerability(self, vulnerability_id: str) -> List[PatchHistoryItem]:
        """FE-5: Return historical patch records for audit and traceability."""
        patches = await self.repo.list_by_vulnerability_ids([vulnerability_id])
        patches_sorted = sorted(patches, key=lambda p: p.get("created_at") or datetime.min)
        return [
            PatchHistoryItem(
                patch_id=p["patch_id"],
                vulnerability_id=p.get("vulnerability_id"),
                vuln_type=p.get("vuln_type"),
                file_path=p.get("file_path"),
                status=p.get("status", ""),
                review_status=p.get("review_status", "pending_review"),
                confidence=p.get("confidence", 0.0),
                version=p.get("version", 1),
                created_at=p.get("created_at"),
            )
            for p in patches_sorted
        ]

    def _run_validations(self, ctx: VulnerabilityContext, unified_diff: str) -> List[ValidationResult]:
        # Wrapper to keep validation logic in PatchValidator.
        return self.validator.validate(ctx, unified_diff)

    def _compute_confidence(self, unified_diff: str, validations: List[ValidationResult]) -> float:
        """
        Tiered confidence model — industry-aligned.

        Tier determination (structural validity first):
          T1 — diff_format failed          → 0.10–0.20  (patch unusable)
          T2 — syntax check failed         → 0.30–0.50  (code would break on apply)
          T3 — apply_diff failed           → 0.50–0.70  (valid fix, context mismatch)
          T4 — all structural checks OK    → 0.75–0.95  (high quality)

        Within each tier the semantic pass ratio refines the score.
        Semantic checks are meaningless if structural checks fail, so they only
        contribute within the tier range — they do not cross tier boundaries.
        """
        if "PLACEHOLDER_FILE" in unified_diff:
            return 0.20  # Prompt error; patch is not usable

        by_name = {v.name: v for v in validations}

        diff_ok   = by_name.get("diff_format",   ValidationResult(name="diff_format",   passed=True, details="")).passed
        syntax_ok = all(
            v.passed for v in validations
            if v.name in {"python_syntax", "js_syntax"}
        )
        apply_ok  = by_name.get("apply_diff",    ValidationResult(name="apply_diff",    passed=True, details="")).passed

        # Semantic ratio: proportion of semantic checks that passed (0.0–1.0)
        sem = [v for v in validations if v.name.startswith("semantic")]
        sem_ratio = (sum(1 for v in sem if v.passed) / len(sem)) if sem else 1.0

        # ── Tier 1: diff format broken — patch is unusable ─────────────────────
        if not diff_ok:
            return round(0.10 + 0.10 * sem_ratio, 2)  # 0.10 – 0.20

        # ── Tier 2: syntax broken — would break the codebase ──────────────────
        if not syntax_ok:
            return round(0.30 + 0.20 * sem_ratio, 2)  # 0.30 – 0.50

        # ── Tier 3: apply failed (context mismatch) — valid fix, can't auto-apply
        if not apply_ok:
            return round(0.50 + 0.20 * sem_ratio, 2)  # 0.50 – 0.70

        # ── Tier 4: all structural checks passed — high quality patch ──────────
        return round(0.75 + 0.20 * sem_ratio, 2)  # 0.75 – 0.95

    def _compute_score_breakdown(
        self,
        validations: List[ValidationResult],
        overall: float,
        generation_attempts: int,
    ) -> dict:
        """
        Multi-dimensional score breakdown — industry standard transparency.
        Structural validity is separate from semantic correctness.
        """
        structural_names = {"diff_format", "python_syntax", "js_syntax", "apply_diff", "ast_python"}
        struct = [v for v in validations if v.name in structural_names]
        sem    = [v for v in validations if v.name.startswith("semantic")]

        struct_score = (sum(1 for v in struct if v.passed) / len(struct)) if struct else 1.0
        sem_score    = (sum(1 for v in sem    if v.passed) / len(sem))    if sem    else 1.0

        if overall >= 0.85:
            label = "HIGH"
        elif overall >= 0.70:
            label = "MEDIUM"
        elif overall >= 0.50:
            label = "LOW"
        else:
            label = "UNVERIFIED"

        return {
            "structural": round(struct_score, 2),
            "semantic":   round(sem_score,    2),
            "overall":    round(overall,       2),
            "label":      label,
            "generation_attempts": generation_attempts,
        }

    def _build_explanation(self, validations: List[ValidationResult], ctx: Optional[VulnerabilityContext] = None) -> str:
        # Human-readable summary for UI (FR-M6.5 — references CWE/OWASP).
        passed = [v.name for v in validations if v.passed]
        failed = [v.name for v in validations if not v.passed]
        parts = [f"AI-generated patch for {ctx.vuln_type if ctx else 'detected vulnerability'}."]
        if ctx and ctx.cwe:
            parts.append(f"Addresses {ctx.cwe}.")
        if ctx and ctx.owasp:
            parts.append(f"Mapped to {ctx.owasp}.")
        if ctx and ctx.source and ctx.sink:
            parts.append(f"Taint flow: {ctx.source} → {ctx.sink}.")
        parts.append(f"Validation — passed: {passed or 'none'}.")
        if failed:
            parts.append(f"Failed: {failed}. Manual review recommended.")
        return " ".join(parts)

    async def _load_context(self, user_id: str, vulnerability_id: Optional[str]) -> Optional[VulnerabilityContext]:
        # Load vulnerability context from scan summary by vulnerability_id.
        if not vulnerability_id:
            return None
        scan = await self.db.scans.find_one({"summary.vulnerabilities.id": vulnerability_id})
        if not scan:
            return None
        summary = scan.get("summary") or {}
        vulns = summary.get("vulnerabilities") or []
        for vuln in vulns:
            if vuln.get("id") == vulnerability_id:
                loc = vuln.get("location") or {}
                evidence = vuln.get("evidence") or {}
                return VulnerabilityContext(
                    vulnerability_id=vulnerability_id,
                    file_path=loc.get("file", ""),
                    language="python" if str(loc.get("file", "")).endswith(".py") else "javascript",
                    vuln_type=vuln.get("type", ""),
                    cwe=vuln.get("cwe"),
                    owasp=vuln.get("owasp"),
                    vulnerable_slice=evidence.get("code_snippet", ""),
                    context_before_after=None,
                    taint_path=evidence.get("data_flow_path", []),
                    sink=evidence.get("sink"),
                    source=evidence.get("source"),
                )
        return None

    async def _sync_patch_to_scan(
        self,
        vulnerability_id: Optional[str],
        patch_id: str,
        status: str,
        confidence: Optional[float],
        validations: List[ValidationResult],
    ) -> None:
        # Write patch status into both summary and top-level vulnerabilities arrays.
        if not vulnerability_id:
            return
        passed = sum(1 for v in validations if v.passed)
        patch_data = {
            "status": status,
            "confidence": confidence,
            "validation_summary": f"{passed}/{len(validations)} passed",
            "patch_id": patch_id,
        }
        await self.db.scans.update_one(
            {"summary.vulnerabilities.id": vulnerability_id},
            {"$set": {"summary.vulnerabilities.$.patch": patch_data}},
        )
        await self.db.scans.update_one(
            {"vulnerabilities.id": vulnerability_id},
            {"$set": {"vulnerabilities.$.patch": patch_data}},
        )
