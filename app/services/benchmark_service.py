from __future__ import annotations

import time
import logging
from datetime import datetime, timezone
from typing import List, Optional
from collections import defaultdict

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorDatabase

from semantic_engine.pipeline import get_pipeline, PipelineConfig
from app.schemas.benchmark import (
    TestCase, TestCaseCreate, BenchmarkRun, CaseResult, CWEMetrics, LeaderboardEntry
)

logger = logging.getLogger(__name__)

TC_COLLECTION  = "benchmark_test_cases"
RUN_COLLECTION = "benchmark_runs"


def _doc_to_test_case(doc: dict) -> TestCase:
    doc["id"] = str(doc.pop("_id"))
    return TestCase(**doc)


def _doc_to_run(doc: dict) -> BenchmarkRun:
    doc["id"] = str(doc.pop("_id"))
    return BenchmarkRun(**doc)


def _metrics(tp: int, fp: int, fn: int, tn: int) -> tuple[float, float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall    = tp / (tp + fn) if (tp + fn) else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fp_rate   = fp / (fp + tn) if (fp + tn) else 0.0
    return round(precision, 4), round(recall, 4), round(f1, 4), round(fp_rate, 4)


class BenchmarkService:
    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        self.db = db

    # ── Test cases ────────────────────────────────────────────────────────────

    async def list_test_cases(
        self,
        cwe: Optional[str] = None,
        language: Optional[str] = None,
        label: Optional[str] = None,
    ) -> List[TestCase]:
        query: dict = {}
        if cwe:      query["cwe"]      = cwe
        if language: query["language"] = language
        if label:    query["label"]    = label
        cursor = self.db[TC_COLLECTION].find(query).sort("cwe", 1)
        return [_doc_to_test_case(d) async for d in cursor]

    async def get_test_case(self, tc_id: str) -> Optional[TestCase]:
        doc = await self.db[TC_COLLECTION].find_one({"_id": ObjectId(tc_id)})
        return _doc_to_test_case(doc) if doc else None

    async def create_test_case(self, data: TestCaseCreate) -> TestCase:
        doc = data.model_dump()
        doc["created_at"] = datetime.now(timezone.utc)
        result = await self.db[TC_COLLECTION].insert_one(doc)
        doc["_id"] = result.inserted_id
        return _doc_to_test_case(doc)

    async def delete_test_case(self, tc_id: str) -> bool:
        result = await self.db[TC_COLLECTION].delete_one({"_id": ObjectId(tc_id)})
        return result.deleted_count > 0

    async def seed_if_empty(self, cases: list[dict]) -> int:
        existing = await self.db[TC_COLLECTION].count_documents({})
        if existing >= len(cases):
            return 0
        # Collection is empty or outdated (fewer docs than seed list) — drop and reseed
        await self.db[TC_COLLECTION].drop()
        docs = [{**c, "created_at": datetime.now(timezone.utc)} for c in cases]
        result = await self.db[TC_COLLECTION].insert_many(docs)
        return len(result.inserted_ids)

    # ── Benchmark runner ──────────────────────────────────────────────────────

    async def run_benchmark(self, enable_llm: bool = False) -> BenchmarkRun:
        test_cases = await self.list_test_cases()
        if not test_cases:
            return BenchmarkRun(run_date=datetime.now(timezone.utc))

        pipeline = get_pipeline(PipelineConfig(enable_llm=enable_llm))
        start_ms = time.time()

        tp = fp = fn = tn = 0
        case_results: List[CaseResult] = []
        cwe_buckets: dict = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0})

        for tc in test_cases:
            try:
                result = await pipeline.analyze_code(
                    filename=f"bench.{tc.language[:2]}",
                    code=tc.code,
                    language=tc.language,
                )
                vulns = result.vulnerabilities if result.success else []
                detected = len(vulns) > 0
                detected_type = vulns[0].get("type") if vulns else None
                confidence = float(vulns[0].get("confidence", 0)) if vulns else 0.0
            except Exception as e:
                logger.warning(f"Benchmark scan failed for {tc.name}: {e}")
                detected, detected_type, confidence = False, None, 0.0

            is_vuln = tc.label == "vulnerable"
            if is_vuln and detected:
                outcome = "TP"; tp += 1; cwe_buckets[tc.cwe]["tp"] += 1
            elif is_vuln and not detected:
                outcome = "FN"; fn += 1; cwe_buckets[tc.cwe]["fn"] += 1
            elif not is_vuln and detected:
                outcome = "FP"; fp += 1; cwe_buckets[tc.cwe]["fp"] += 1
            else:
                outcome = "TN"; tn += 1; cwe_buckets[tc.cwe]["tn"] += 1

            case_results.append(CaseResult(
                test_case_id=tc.id,
                name=tc.name,
                cwe=tc.cwe,
                vuln_type=tc.vuln_type,
                label=tc.label,
                detected=detected,
                detected_type=detected_type,
                outcome=outcome,
                confidence=confidence,
            ))

        precision, recall, f1, fp_rate = _metrics(tp, fp, fn, tn)

        per_cwe = []
        for cwe, b in cwe_buckets.items():
            p, r, f, _ = _metrics(b["tp"], b["fp"], b["fn"], b["tn"])
            per_cwe.append(CWEMetrics(cwe=cwe, precision=p, recall=r, f1=f, **b))

        if enable_llm:
            try:
                from semantic_engine.classifier.llm_service import get_llm_service
                model_used = get_llm_service()._pool.current_model
            except Exception:
                import os
                model_used = os.environ.get("GROQ_MODEL", os.environ.get("LLM_MODEL", "unknown"))
        else:
            model_used = "static-only"

        run = BenchmarkRun(
            run_date=datetime.now(timezone.utc),
            model_used=model_used,
            run_type="synthetic",
            total=len(test_cases),
            tp=tp, fp=fp, fn=fn, tn=tn,
            precision=precision, recall=recall, f1=f1, fp_rate=fp_rate,
            per_cwe=per_cwe,
            case_results=case_results,
            duration_ms=int((time.time() - start_ms) * 1000),
        )

        doc = run.model_dump(exclude={"id"})
        result = await self.db[RUN_COLLECTION].insert_one(doc)
        run.id = str(result.inserted_id)
        return run

    # ── Field benchmark (AI-oracle confirmed real findings) ───────────────────

    async def run_field_benchmark(self) -> BenchmarkRun:
        """
        Compute field precision from AI-oracle verdicts on real scan findings.

        Every finding in confirmed_findings was already detected by the scanner
        during a real scan.  The oracle then judged each one:
          confirmed → TP  (scanner detected it AND oracle agrees it is exploitable)
          rejected  → FP  (scanner detected it BUT oracle says it is not exploitable)

        FN / recall cannot be measured here because we only see findings the
        scanner already reported — we would need to scan clean files to find misses.
        """
        from app.services.confirmation_service import CONFIRMED_COLLECTION

        field_cases = await self.db[CONFIRMED_COLLECTION].find(
            {"oracle_verdict": {"$in": ["confirmed", "rejected"]}}
        ).to_list(None)

        if not field_cases:
            return BenchmarkRun(
                run_date=datetime.now(timezone.utc),
                model_used="oracle-field",
                run_type="field",
                total=0,
            )

        start_ms = time.time()
        tp = fp = 0
        fn = tn = 0          # FN/TN cannot be measured — left as 0
        case_results: List[CaseResult] = []
        cwe_buckets: dict = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0})

        for fc in field_cases:
            cwe       = fc.get("cwe") or "UNKNOWN"
            vuln_type = fc.get("vuln_type", "")
            name      = f"{vuln_type} @ {fc.get('file_path','?')}"
            fid       = str(fc.get("_id", ""))
            confidence = float(fc.get("oracle_confidence", 0))

            # Scanner always detected these (they came from real scans)
            detected = True

            if fc["oracle_verdict"] == "confirmed":
                outcome = "TP"; tp += 1; cwe_buckets[cwe]["tp"] += 1
            else:
                outcome = "FP"; fp += 1; cwe_buckets[cwe]["fp"] += 1

            case_results.append(CaseResult(
                test_case_id=fid,
                name=name,
                cwe=cwe,
                vuln_type=vuln_type,
                label="vulnerable" if fc["oracle_verdict"] == "confirmed" else "safe",
                detected=detected,
                detected_type=vuln_type,
                outcome=outcome,
                confidence=confidence,
            ))

        # Precision = TP / (TP + FP).  Recall is undefined (FN=0 by construction).
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        precision = round(precision, 4)
        # F1 uses only precision here since recall cannot be computed.
        # We surface this honestly in the UI subtitle.
        f1       = precision
        recall   = 1.0 if tp else 0.0   # placeholder — scanner found all confirmed ones
        fp_rate  = round(fp / (tp + fp), 4) if (tp + fp) else 0.0

        per_cwe = []
        for cwe, b in cwe_buckets.items():
            p = b["tp"] / (b["tp"] + b["fp"]) if (b["tp"] + b["fp"]) else 0.0
            per_cwe.append(CWEMetrics(
                cwe=cwe, precision=round(p, 4), recall=1.0, f1=round(p, 4), **b
            ))

        import os
        oracle_model = os.environ.get("GROQ_MODEL", "oracle")

        run = BenchmarkRun(
            run_date=datetime.now(timezone.utc),
            model_used=oracle_model,
            run_type="field",
            total=len(field_cases),
            tp=tp, fp=fp, fn=fn, tn=tn,
            precision=precision, recall=recall, f1=f1, fp_rate=fp_rate,
            per_cwe=per_cwe,
            case_results=case_results,
            duration_ms=int((time.time() - start_ms) * 1000),
        )

        doc    = run.model_dump(exclude={"id"})
        result = await self.db[RUN_COLLECTION].insert_one(doc)
        run.id = str(result.inserted_id)
        return run

    # ── Runs ──────────────────────────────────────────────────────────────────

    async def list_runs(self, limit: int = 20, run_type: str = "synthetic") -> List[BenchmarkRun]:
        query = {"run_type": run_type} if run_type else {}
        cursor = self.db[RUN_COLLECTION].find(query).sort("run_date", -1).limit(limit)
        runs = []
        async for doc in cursor:
            r = _doc_to_run(doc)
            r.case_results = []   # strip per-case detail from list view
            runs.append(r)
        return runs

    async def get_run(self, run_id: str) -> Optional[BenchmarkRun]:
        doc = await self.db[RUN_COLLECTION].find_one({"_id": ObjectId(run_id)})
        return _doc_to_run(doc) if doc else None

    # ── Leaderboard ───────────────────────────────────────────────────────────

    async def leaderboard(self) -> List[LeaderboardEntry]:
        cursor = self.db[RUN_COLLECTION].find({"run_type": "synthetic"}).sort("run_date", -1)
        by_model: dict = defaultdict(list)
        async for doc in cursor:
            by_model[doc.get("model_used", "unknown")].append(doc)

        entries = []
        for model, docs in by_model.items():
            f1s        = [d.get("f1", 0) for d in docs]
            precisions = [d.get("precision", 0) for d in docs]
            recalls    = [d.get("recall", 0) for d in docs]
            last_run   = docs[0].get("run_date")

            # trend: compare last two runs
            trend = "—"
            if len(f1s) >= 2:
                trend = "↑" if f1s[0] > f1s[1] else ("↓" if f1s[0] < f1s[1] else "—")

            entries.append(LeaderboardEntry(
                model_used=model,
                runs=len(docs),
                best_f1=round(max(f1s), 4),
                avg_precision=round(sum(precisions) / len(precisions), 4),
                avg_recall=round(sum(recalls) / len(recalls), 4),
                avg_f1=round(sum(f1s) / len(f1s), 4),
                last_run=last_run,
                trend=trend,
            ))

        return sorted(entries, key=lambda e: e.best_f1, reverse=True)
