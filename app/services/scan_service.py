import asyncio
import tempfile
import os
import time
import uuid
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime
import logging

from semantic_engine.pipeline import get_pipeline, PipelineConfig

logger = logging.getLogger(__name__)


# Singleton instance
_scan_service_instance = None


def get_scan_service():
    """Get or create the singleton ScanService instance"""
    global _scan_service_instance
    if _scan_service_instance is None:
        _scan_service_instance = ScanService()
    return _scan_service_instance


class ScanService:
    def __init__(self) -> None:
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self.pipeline = get_pipeline(PipelineConfig(enable_llm=True))

    def start(
        self,
        code: Optional[str] = None,
        language: Optional[str] = None,
        filename: Optional[str] = None,
        repo_id: Optional[int] = None,
        branch: str = "main",
        scan_mode: str = "DEEP"
    ) -> tuple[str, str]:
        """
        Start a scan with either direct code or repository.
        Returns (scan_id, input_type)
        """
        scan_id = f"scan-{uuid.uuid4().hex[:12]}"
        logger.info(f"[SCAN_SERVICE] Creating new scan: {scan_id}")
        
        if code:
            # DIRECT CODE SCAN
            input_type = "DIRECT_CODE"
            logger.info(f"[SCAN_SERVICE] Storing job in self.jobs. Instance ID: {id(self)}")
            self.jobs[scan_id] = {
                "state": "PENDING",
                "progress": 0,
                "logs": [],
                "started_at": None,
                "finished_at": None,
                "summary": None,
                "input_type": input_type,
                "current_file": filename or "code.py",
                "files_scanned": 0,
                "total_files": 1,
                "vulnerabilities": []
            }
            
            # Start background task for direct code scan
            asyncio.create_task(
                self._run_direct_code_scan(scan_id, code, language, filename, scan_mode)
            )
        else:
            # REPOSITORY SCAN
            input_type = "REPOSITORY"
            self.jobs[scan_id] = {
                "state": "PENDING",
                "progress": 0,
                "logs": [],
                "started_at": None,
                "finished_at": None,
                "summary": None,
                "input_type": input_type,
                "current_file": None,
                "files_scanned": 0,
                "total_files": 0,
                "vulnerabilities": []
            }
            
            # Start background task for repository scan
            asyncio.create_task(
                self._run_repository_scan(scan_id, repo_id, branch, scan_mode)
            )
        
        return scan_id, input_type

    async def _run_direct_code_scan(
        self,
        scan_id: str,
        code: str,
        language: str,
        filename: Optional[str],
        scan_mode: str
    ):
        """Process direct code scan asynchronously"""
        job = self.jobs[scan_id]
        start_time = time.time()
        
        try:
            # Update status to RUNNING
            job["state"] = "RUNNING"
            job["started_at"] = datetime.utcnow().isoformat()
            job["logs"].append(f"[INFO] Starting direct code scan")
            job["logs"].append(f"[INFO] Language: {language}")
            job["logs"].append(f"[INFO] Lines of code: {len(code.split(chr(10)))}")
            job["progress"] = 10
            
            # Determine file extension
            ext_map = {
                "python": ".py",
                "javascript": ".js",
                "typescript": ".ts",
                "java": ".java",
                "c": ".c",
                "cpp": ".cpp",
                "go": ".go",
                "php": ".php"
            }
            ext = ext_map.get(language, ".txt")
            
            # Use provided filename or generate one
            if not filename:
                filename = f"code{ext}"
            
            job["current_file"] = filename
            job["logs"].append(f"[INFO] Analyzing file: {filename}")
            job["progress"] = 25
            
            # Create temporary file
            with tempfile.NamedTemporaryFile(
                mode='w',
                suffix=ext,
                delete=False,
                encoding='utf-8'
            ) as tmp_file:
                tmp_file.write(code)
                tmp_path = tmp_file.name
            
            try:
                # Run semantic analysis
                job["logs"].append(f"[INFO] Building semantic graph...")
                job["logs"].append(f"[DEBUG] Code to analyze: {code[:200]}...")
                job["progress"] = 40
                
                result = await self.pipeline.analyze_code(
                    filename=filename,
                    code=code,
                    language=language
                )
                
                job["progress"] = 80
                job["logs"].append(f"[INFO] Graph built: {result.graph_nodes} nodes, {result.graph_edges} edges")
                job["logs"].append(f"[INFO] Rules executed: {result.rules_executed}")
                job["logs"].append(f"[INFO] Slices found: {len(result.slices) if hasattr(result, 'slices') else 'N/A'}")
                job["logs"].append(f"[INFO] Vulnerabilities found: {result.vulnerabilities_found}")
                job["logs"].append(f"[DEBUG] Vulnerabilities: {result.vulnerabilities}")
                
                # Store vulnerabilities and graph data
                job["vulnerabilities"] = result.vulnerabilities
                job["graph_data"] = result.graph_data  # Store for visualization
                job["files_scanned"] = 1
                
                # Build summary
                by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                for vuln in result.vulnerabilities:
                    severity = vuln.get("severity", "low")
                    by_severity[severity] = by_severity.get(severity, 0) + 1
                
                duration = time.time() - start_time
                
                job["summary"] = {
                    "scan_id": scan_id,
                    "status": "COMPLETED",
                    "input_type": "DIRECT_CODE",
                    "total_files": 1,
                    "files_scanned": 1,
                    "vulnerabilities_found": result.vulnerabilities_found,
                    "by_severity": by_severity,
                    "duration_seconds": round(duration, 2),
                    "created_at": job["started_at"],
                    "completed_at": datetime.utcnow().isoformat()
                }
                
                job["state"] = "COMPLETED"
                job["finished_at"] = datetime.utcnow().isoformat()
                job["progress"] = 100
                job["logs"].append(f"[SUCCESS] Scan completed in {duration:.2f}s")
                
            finally:
                # Clean up temporary file
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                    
        except Exception as e:
            logger.error(f"Direct code scan failed: {e}", exc_info=True)
            job["state"] = "FAILED"
            job["finished_at"] = datetime.utcnow().isoformat()
            job["logs"].append(f"[ERROR] Scan failed: {str(e)}")
            job["summary"] = {
                "scan_id": scan_id,
                "status": "FAILED",
                "error": str(e)
            }

    async def _run_repository_scan(
        self,
        scan_id: str,
        repo_id: int,
        branch: str,
        scan_mode: str
    ):
        """Process repository scan asynchronously"""
        job = self.jobs[scan_id]
        start_time = time.time()
        
        try:
            # Update status to RUNNING
            job["state"] = "RUNNING"
            job["started_at"] = datetime.utcnow().isoformat()
            job["logs"].append(f"[INFO] Starting repository scan")
            job["logs"].append(f"[INFO] Repository ID: {repo_id}")
            job["logs"].append(f"[INFO] Branch: {branch}")
            job["progress"] = 5
            
            # Get repository from database (TODO: implement actual DB lookup)
            job["logs"].append(f"[INFO] Fetching repository details...")
            # repo = await get_repository_by_id(repo_id)
            # For now, simulate repository
            repo_url = f"https://github.com/example/repo-{repo_id}"
            
            job["logs"].append(f"[INFO] Repository URL: {repo_url}")
            job["progress"] = 10
            
            # Clone/fetch repository (TODO: implement actual git operations)
            job["logs"].append(f"[INFO] Cloning repository...")
            await asyncio.sleep(1)  # Simulate cloning
            
            # For now, we'll scan a mock directory structure
            # In production, this would scan the actual cloned repo
            job["logs"].append(f"[WARN] Repository scanning not yet fully implemented")
            job["logs"].append(f"[INFO] This is a placeholder - will scan actual repos in production")
            
            # Simulate finding files
            mock_files = [
                "app.py",
                "models/user.py",
                "routes/auth.py",
                "utils/db.py"
            ]
            
            job["total_files"] = len(mock_files)
            job["progress"] = 20
            
            all_vulnerabilities = []
            
            # Scan each file
            for i, file_path in enumerate(mock_files):
                job["current_file"] = file_path
                job["logs"].append(f"[INFO] Scanning {file_path}...")
                
                # Simulate file scanning (would be actual analysis in production)
                await asyncio.sleep(0.5)
                
                job["files_scanned"] = i + 1
                job["progress"] = 20 + int((i + 1) / len(mock_files) * 70)
                
                job["logs"].append(f"[INFO] {file_path}: Analysis complete")
            
            # Build summary
            by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            duration = time.time() - start_time
            
            job["summary"] = {
                "scan_id": scan_id,
                "status": "COMPLETED",
                "input_type": "REPOSITORY",
                "total_files": len(mock_files),
                "files_scanned": len(mock_files),
                "vulnerabilities_found": len(all_vulnerabilities),
                "by_severity": by_severity,
                "duration_seconds": round(duration, 2),
                "created_at": job["started_at"],
                "completed_at": datetime.utcnow().isoformat()
            }
            
            job["vulnerabilities"] = all_vulnerabilities
            job["state"] = "COMPLETED"
            job["finished_at"] = datetime.utcnow().isoformat()
            job["progress"] = 100
            job["logs"].append(f"[SUCCESS] Repository scan completed in {duration:.2f}s")
            
        except Exception as e:
            logger.error(f"Repository scan failed: {e}", exc_info=True)
            job["state"] = "FAILED"
            job["finished_at"] = datetime.utcnow().isoformat()
            job["logs"].append(f"[ERROR] Scan failed: {str(e)}")
            job["summary"] = {
                "scan_id": scan_id,
                "status": "FAILED",
                "error": str(e)
            }

    def status(self, scan_id: str) -> Dict[str, Any]:
        job = self.jobs.get(scan_id)
        if not job:
            return {"state": "NOT_FOUND", "progress": 0}
        
        return {
            "state": job["state"],
            "progress": job["progress"],
            "started_at": job.get("started_at"),
            "finished_at": job.get("finished_at"),
            "current_file": job.get("current_file"),
            "files_scanned": job.get("files_scanned", 0),
            "total_files": job.get("total_files", 0)
        }

    def logs(self, scan_id: str) -> Dict[str, Any]:
        job = self.jobs.get(scan_id)
        if not job:
            return {"logs": []}
        return {"logs": job["logs"][-100:]}  # last 100 logs

    def summary(self, scan_id: str) -> Dict[str, Any]:
        job = self.jobs.get(scan_id)
        if not job:
            return None
        
        summary = job.get("summary")
        if summary and job.get("vulnerabilities"):
            print(f"[DEBUG] Adding {len(job['vulnerabilities'])} vulnerabilities to summary")
            summary["vulnerabilities"] = job["vulnerabilities"]
        else:
            print(f"[DEBUG] Not adding vulnerabilities: summary={summary is not None}, vulns={len(job.get('vulnerabilities', []))}")
        
        return summary

    def cancel(self, scan_id: str) -> Dict[str, Any]:
        job = self.jobs.get(scan_id)
        if not job:
            return {"state": "NOT_FOUND"}
        job["state"] = "CANCELLED"
        job["finished_at"] = datetime.utcnow().isoformat()
        job["logs"].append("[INFO] Scan cancelled by user")
        return {"state": "CANCELLED"}
