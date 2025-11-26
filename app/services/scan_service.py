import asyncio
import random
import time
import uuid
from typing import Dict, Any

from app.domain.mock.mock_analyzer_engine import MockAnalyzerEngine


class ScanService:
    def __init__(self) -> None:
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self.engine = MockAnalyzerEngine()

    def start(self, repo_id: int, branch: str, mode: str) -> str:
        scan_id = uuid.uuid4().hex[:12]
        self.jobs[scan_id] = {
            "state": "QUEUED",
            "progress": 0,
            "logs": [],
            "started_at": None,
            "finished_at": None,
            "summary": None,
        }
        asyncio.create_task(self._run_job(scan_id, repo_id, branch, mode))
        return scan_id

    async def _run_job(self, scan_id: str, repo_id: int, branch: str, mode: str):
        job = self.jobs[scan_id]
        job["state"] = "RUNNING"
        job["started_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        for i in range(1, 11):
            await asyncio.sleep(0.4)
            job["progress"] = i * 10
            job["logs"].append(f"[{i}/10] Analyzing ... {uuid.uuid4().hex[:6]}")
        analysis = self.engine.analyze(repo_id, branch, mode)
        job["summary"] = {
            "scan_id": scan_id,
            "severity": analysis["severity"],
            "ai_confidence": analysis["ai_confidence"],
            "report_id": random.randint(10, 99),
        }
        job["state"] = "COMPLETED"
        job["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def status(self, scan_id: str) -> Dict[str, Any]:
        return self.jobs.get(scan_id) or {"state": "NOT_FOUND", "progress": 0}

    def logs(self, scan_id: str) -> Dict[str, Any]:
        job = self.jobs.get(scan_id)
        if not job:
            return {"logs": []}
        return {"logs": job["logs"][-50:]}  # last 50

    def summary(self, scan_id: str) -> Dict[str, Any]:
        job = self.jobs.get(scan_id)
        return job.get("summary") if job else None

    def cancel(self, scan_id: str) -> Dict[str, Any]:
        job = self.jobs.get(scan_id)
        if not job:
            return {"state": "NOT_FOUND"}
        job["state"] = "CANCELLED"
        return {"state": "CANCELLED"}
