"""
ConfirmationService — AI-oracle confirmation for real scan findings.

After a real scan completes, this service:
  1. Runs each HIGH/CRITICAL finding through the exploit LLM pool (stronger oracle models).
  2. Stores oracle verdicts in `confirmed_findings` MongoDB collection.
  3. Randomly flags 10% of decisions for human spot-check review.
  4. Provides field metrics: real-world precision measured against oracle ground truth.

Oracle model pool (exploit role): DeepSeek-V3 → Llama-4-Maverick → GPT-4o → Groq DeepSeek-R1
These are the strongest models in the system, used as the confirmation oracle.
"""
from __future__ import annotations

import hashlib
import logging
import os
import random
from datetime import datetime, timezone
from typing import Optional

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorDatabase

from semantic_engine.classifier.exploit_llm_service import get_exploit_service

logger = logging.getLogger(__name__)

CONFIRMED_COLLECTION = "confirmed_findings"
SPOTCHECK_RATE = 0.10

_LANG_MAP = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".tsx": "typescript", ".jsx": "javascript",
}


def _infer_language(file_path: str) -> str:
    import os.path
    ext = os.path.splitext(str(file_path))[1].lower()
    return _LANG_MAP.get(ext, "python")


def _finding_hash(finding: dict) -> str:
    loc  = finding.get("location") or {}
    key  = f"{finding.get('type','')}{loc.get('file','')}{loc.get('start_line','')}"
    code = (
        (finding.get("evidence") or {}).get("code_slice") or
        (finding.get("evidence") or {}).get("source_code") or ""
    )[:200]
    return hashlib.sha256((key + code).encode()).hexdigest()[:16]


class ConfirmationService:
    """
    Oracle-based confirmation for real scan findings.
    Designed to run as a fire-and-forget background task after each scan completes.
    """

    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        self.db     = db
        self._oracle = get_exploit_service()

    # ── Background task ───────────────────────────────────────────────────────

    async def confirm_scan_findings(self, scan_id: str, findings: list[dict]) -> dict:
        """
        Oracle-confirm all HIGH/CRITICAL findings from a completed scan.
        Skips duplicates already confirmed from previous scans (by finding_hash).
        Returns summary counts for logging only — caller does not await the result.
        """
        if not self._oracle.is_available:
            logger.debug("[confirmation] oracle pool unavailable, skipping scan %s", scan_id)
            return {"confirmed": 0, "rejected": 0, "skipped": len(findings)}

        candidates = [
            f for f in findings
            if f.get("severity", "").lower() in ("high", "critical")
        ]
        confirmed = rejected = skipped = 0

        for finding in candidates:
            fhash = _finding_hash(finding)

            # Skip if already confirmed from a previous scan
            if await self.db[CONFIRMED_COLLECTION].find_one({"finding_hash": fhash}, {"_id": 1}):
                skipped += 1
                continue

            code_slice = (
                (finding.get("evidence") or {}).get("code_slice") or
                (finding.get("evidence") or {}).get("source_code") or ""
            )
            file_path = (finding.get("location") or {}).get("file", "unknown")
            severity  = finding.get("severity", "high")

            try:
                exploit = await self._oracle.generate_exploit(
                    code_snippet=code_slice,
                    vuln_type=finding.get("type", "unknown"),
                    cwe=finding.get("cwe"),
                    owasp=finding.get("owasp"),
                    severity=severity,
                    file_path=file_path,
                )
            except Exception as exc:
                logger.error("[confirmation] oracle error on %s: %s", fhash, exc)
                skipped += 1
                continue

            if exploit is None:
                skipped += 1
                continue

            verdict   = "confirmed" if exploit.exploitable else "rejected"
            spotcheck = random.random() < SPOTCHECK_RATE

            await self.db[CONFIRMED_COLLECTION].insert_one({
                "scan_id":            scan_id,
                "finding_hash":       fhash,
                "vuln_type":          finding.get("type", ""),
                "cwe":                finding.get("cwe") or "",
                "severity":           severity,
                "language":           _infer_language(file_path),
                "file_path":          file_path,
                "start_line":         (finding.get("location") or {}).get("start_line"),
                "code_snippet":       code_slice[:1500],
                "oracle_verdict":     verdict,
                "oracle_confidence":  exploit.confidence,
                "oracle_reasoning":   exploit.impact or "",
                "oracle_model":       os.environ.get("GROQ_MODEL", "unknown"),
                "exploit_type":       exploit.exploit_type or "",
                "poc_code":           exploit.poc_code or "",
                "spotcheck_required": spotcheck,
                "human_verdict":      None,
                "human_reviewer":     None,
                "human_reviewed_at":  None,
                "created_at":         datetime.now(timezone.utc),
            })

            if verdict == "confirmed":
                confirmed += 1
            else:
                rejected += 1

        logger.info(
            "[confirmation] scan %s: confirmed=%d rejected=%d skipped=%d",
            scan_id, confirmed, rejected, skipped,
        )
        return {"confirmed": confirmed, "rejected": rejected, "skipped": skipped}

    # ── Field metrics ─────────────────────────────────────────────────────────

    async def get_field_metrics(self) -> dict:
        total      = await self.db[CONFIRMED_COLLECTION].count_documents({})
        confirmed  = await self.db[CONFIRMED_COLLECTION].count_documents({"oracle_verdict": "confirmed"})
        rejected   = await self.db[CONFIRMED_COLLECTION].count_documents({"oracle_verdict": "rejected"})
        sp_pending = await self.db[CONFIRMED_COLLECTION].count_documents(
            {"spotcheck_required": True, "human_verdict": None}
        )

        field_precision = confirmed / (confirmed + rejected) if (confirmed + rejected) else 0.0

        reviewed = await self.db[CONFIRMED_COLLECTION].find(
            {"human_verdict": {"$ne": None}},
            {"oracle_verdict": 1, "human_verdict": 1},
        ).to_list(None)

        human_agreement = None
        if reviewed:
            agreed = sum(1 for r in reviewed if r["oracle_verdict"] == r["human_verdict"])
            human_agreement = round(agreed / len(reviewed), 4)

        return {
            "total":                total,
            "oracle_confirmed":     confirmed,
            "oracle_rejected":      rejected,
            "field_precision":      round(field_precision, 4),
            "spotcheck_pending":    sp_pending,
            "spotcheck_reviewed":   len(reviewed),
            "human_agreement_rate": human_agreement,
        }

    # ── Spot-check ────────────────────────────────────────────────────────────

    async def list_spotcheck_items(self, only_pending: bool = True) -> list[dict]:
        query: dict = {"spotcheck_required": True}
        if only_pending:
            query["human_verdict"] = None
        cursor = (
            self.db[CONFIRMED_COLLECTION]
            .find(query)
            .sort("created_at", -1)
            .limit(50)
        )
        items = []
        async for doc in cursor:
            doc["id"] = str(doc.pop("_id"))
            items.append(doc)
        return items

    async def submit_verdict(
        self, finding_id: str, verdict: str, reviewer_id: str
    ) -> bool:
        result = await self.db[CONFIRMED_COLLECTION].update_one(
            {"_id": ObjectId(finding_id)},
            {"$set": {
                "human_verdict":     verdict,
                "human_reviewer":    reviewer_id,
                "human_reviewed_at": datetime.now(timezone.utc),
            }},
        )
        return result.modified_count > 0

    # ── Confirmed findings list ───────────────────────────────────────────────

    async def list_confirmed_findings(
        self,
        verdict: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        query: dict = {}
        if verdict:
            query["oracle_verdict"] = verdict
        cursor = (
            self.db[CONFIRMED_COLLECTION]
            .find(query)
            .sort("created_at", -1)
            .limit(limit)
        )
        items = []
        async for doc in cursor:
            doc["id"] = str(doc.pop("_id"))
            items.append(doc)
        return items
