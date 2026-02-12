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
)
from app.patch_module.prompt_builder import PromptBuilder
from app.patch_module.patch_llm_service import PatchLLMService
from app.patch_module.patch_validator import PatchValidator
from app.patch_module.patch_repository import PatchRepository
from app.patch_module.guards import enforce_rate_limit, enforce_slice_length, reject_secrets

logger = logging.getLogger(__name__)


class PatchOrchestrator:
    def __init__(self, db: AsyncIOMotorDatabase):
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
        ctx = context or await self._load_context(user_id, vulnerability_id)
        if ctx is None:
            raise ResourceNotFoundException("Vulnerability context not found")

        await enforce_rate_limit(self.db, user_id)
        enforce_slice_length(ctx.vulnerable_slice)
        reject_secrets(ctx.vulnerable_slice)

        prompt = PromptBuilder.build_prompt(
            language=ctx.language,
            vuln_type=ctx.vuln_type,
            cwe=ctx.cwe,
            owasp=ctx.owasp,
            vulnerable_slice=ctx.vulnerable_slice,
            context_before_after=ctx.context_before_after,
            taint_path=ctx.taint_path,
            sink=ctx.sink,
            source=ctx.source,
        )

        unified_diff = await self.llm.generate_patch(prompt)
        validations = self._run_validations(ctx, unified_diff)
        status = "generated" if all(v.passed for v in validations) else "rejected"

        confidence = self._compute_confidence(unified_diff, validations)
        explanation = self._build_explanation(validations)

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
            "validations": [v.model_dump() for v in validations],
            "status": status,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        })
        await self._sync_patch_to_scan(ctx.vulnerability_id, patch_id, status, confidence, validations)

        return PatchGenerateResponse(
            patch_id=patch_id,
            unified_diff=unified_diff,
            explanation=explanation,
            confidence=confidence,
            validations=validations,
            status=status,
        )

    async def validate(self, patch_id: str) -> PatchValidateResponse:
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
        await self.repo.update_patch(patch_id, {
            "validations": [v.model_dump() for v in validations],
            "status": status,
        })
        await self._sync_patch_to_scan(ctx.vulnerability_id, patch_id, status, patch.get("confidence"), validations)
        return PatchValidateResponse(patch_id=patch_id, validations=validations, status=status)

    async def apply(self, patch_id: str, user_id: str, repo_id: Optional[str]) -> PatchApplyResponse:
        patch = await self.repo.get_patch(patch_id)
        if not patch:
            raise ResourceNotFoundException("Patch not found")

        pending_apply_id = await self.repo.create_pending_apply(patch_id, user_id, repo_id)
        branch = f"vulcan/patch-{patch_id[:8]}"
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
        patch = await self.repo.get_patch(patch_id)
        if not patch:
            raise ResourceNotFoundException("Patch not found")
        return patch.get("unified_diff", "")

    def _run_validations(self, ctx: VulnerabilityContext, unified_diff: str) -> List[ValidationResult]:
        return self.validator.validate(ctx, unified_diff)

    def _compute_confidence(self, unified_diff: str, validations: List[ValidationResult]) -> float:
        base = 0.8
        if "PLACEHOLDER_FILE" in unified_diff:
            base = 0.5
        penalties = sum(0.2 for v in validations if not v.passed)
        confidence = max(0.1, base - penalties)
        return round(confidence, 2)

    def _build_explanation(self, validations: List[ValidationResult]) -> str:
        passed = [v.name for v in validations if v.passed]
        failed = [v.name for v in validations if not v.passed]
        return f"Automated patch generation. Passed: {passed}. Failed: {failed}."

    async def _load_context(self, user_id: str, vulnerability_id: Optional[str]) -> Optional[VulnerabilityContext]:
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
