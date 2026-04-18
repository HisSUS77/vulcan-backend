import asyncio
import tempfile
import os
import time
import uuid
from datetime import datetime
import logging
from typing import Dict, Any, Optional
from pathlib import Path
import shutil
import tarfile
import zipfile
import subprocess

from motor.motor_asyncio import AsyncIOMotorDatabase

from semantic_engine.pipeline import get_pipeline, PipelineConfig
from app.enums.role import UserRole
from app.schemas.scan import ScanStatusRead, ScanSummary
from app.db.mongo import to_object_id
from app.core.config import settings
from app.patch_module.patch_repository import PatchRepository
from app.core.trace import trace_step

logger = logging.getLogger(__name__)


class ScanService:
    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        self.db = db
        self.pipeline = get_pipeline(PipelineConfig(enable_llm=True))

    async def start(
        self,
        user_id: str,
        code: Optional[str] = None,
        language: Optional[str] = None,
        filename: Optional[str] = None,
        repo_id: Optional[int] = None,
        branch: str = "main",
        scan_mode: str = "DEEP",
        repo_url: Optional[str] = None,
        repo_provider: Optional[str] = None,
        repo_token: Optional[str] = None,
        file_paths: Optional[list[str]] = None,
    ) -> tuple[str, str]:
        trace_step("Service: ScanService.start() (app/services/scan_service.py)")
        scan_id = f"scan-{uuid.uuid4().hex[:12]}"
        input_type = "DIRECT_CODE" if code else "REPOSITORY"

        object_id = to_object_id(user_id)
        if not object_id:
            raise ValueError("Invalid user_id")

        now = datetime.utcnow()
        scan_doc: Dict[str, Any] = {
            "scan_id": scan_id,
            "user_id": object_id,
            "repo_id": repo_id,
            "branch": branch,
            "mode": scan_mode,
            "repo_url": repo_url,
            "repo_provider": repo_provider,
            "file_paths": file_paths or None,
            "state": "PENDING",
            "progress": 0,
            "started_at": None,
            "finished_at": None,
            "created_at": now,
            "updated_at": now,
            "input_type": input_type,
            "current_file": None,
            "files_scanned": 0,
            "total_files": 0,
            "vulnerabilities": [],
            "summary": None,
            "logs": [],
        }
        await self.db.scans.insert_one(scan_doc)

        if code:
            trace_step("Dispatch: create_task(_run_direct_code_scan)")
            asyncio.create_task(
                self._run_direct_code_scan(scan_id, code, language, filename, scan_mode)
            )
        else:
            trace_step("Dispatch: create_task(_run_repository_scan)")
            asyncio.create_task(
                self._run_repository_scan(
                    scan_id,
                    repo_id,
                    branch,
                    scan_mode,
                    repo_url,
                    repo_provider,
                    repo_token,
                    file_paths,
                )
            )

        return scan_id, input_type

    def _detect_language(self, path: Path) -> Optional[str]:
        ext = path.suffix.lower()
        return {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".jsx": "javascript",
            ".html": "html",
            ".htm": "html",
            ".jinja": "html",
            ".j2": "html",
            ".ejs": "html",
            ".hbs": "html",
            ".handlebars": "html",
            ".mustache": "html",
            ".pug": "html",
        }.get(ext)

    def _collect_source_files(self, root: Path) -> list[Path]:
        files = []
        for path in root.rglob("*"):
            if path.is_file():
                lang = self._detect_language(path)
                if lang:
                    files.append(path)
        return files

    def _path_key(self, path: Optional[str]) -> str:
        if not path:
            return ""
        normalized = str(path).replace("\\", "/")
        return normalized.lower() if os.name == "nt" else normalized

    def _normalize_repo_path(
        self,
        repo_root: Path,
        file_path: Optional[str],
        rel_paths: Optional[list[str]] = None,
    ) -> Optional[str]:
        if not file_path:
            return None
        path_str = str(file_path).replace("\\", "/")
        try:
            path_obj = Path(path_str)
            if path_obj.is_absolute():
                rel = path_obj.resolve().relative_to(repo_root.resolve())
                path_str = str(rel).replace("\\", "/")
        except Exception:
            pass
        repo_root_str = str(repo_root.resolve()).replace("\\", "/")
        if path_str.startswith(repo_root_str + "/"):
            path_str = path_str[len(repo_root_str) + 1 :]
        if path_str.startswith("./"):
            path_str = path_str[2:]
        if rel_paths and (":" in path_str or path_str.startswith("/")):
            norm = self._path_key(path_str)
            best = None
            for rel in rel_paths:
                rel_norm = self._path_key(rel)
                if norm.endswith("/" + rel_norm) or norm.endswith(rel_norm):
                    if not best or len(rel_norm) > len(self._path_key(best)):
                        best = rel
            if best:
                path_str = best
        return path_str

    def _dedupe_vulnerabilities(
        self,
        repo_root: Optional[Path],
        vulnerabilities: list[dict],
        rel_paths: Optional[list[str]] = None,
    ) -> list[dict]:
        if not vulnerabilities:
            return []
        deduped: list[dict] = []
        seen: dict[tuple, dict] = {}
        for vuln in vulnerabilities:
            location = vuln.get("location") or {}
            file_path = location.get("file")
            if repo_root:
                normalized = self._normalize_repo_path(repo_root, file_path, rel_paths)
            else:
                normalized = str(file_path).replace("\\", "/") if file_path else None
            if normalized:
                location["file"] = normalized
                vuln["location"] = location
            evidence = vuln.get("evidence") or {}
            key = (
                str(vuln.get("type") or ""),
                self._path_key(normalized),
                location.get("start_line"),
                location.get("end_line"),
                str(evidence.get("sink") or ""),
                str(evidence.get("source") or ""),
            )
            existing = seen.get(key)
            if existing:
                existing_conf = existing.get("confidence") or 0
                new_conf = vuln.get("confidence") or 0
                if new_conf > existing_conf:
                    idx = deduped.index(existing)
                    deduped[idx] = vuln
                    seen[key] = vuln
                continue
            seen[key] = vuln
            deduped.append(vuln)
        return deduped

    def _filter_graph_for_file(
        self,
        graph_data: dict,
        repo_root: Path,
        rel_path: str
    ) -> dict:
        nodes = []
        node_ids = set()
        has_file_info = False
        for node in graph_data.get("nodes", []):
            file_prop = (node.get("properties") or {}).get("file")
            if file_prop:
                has_file_info = True
            normalized = self._normalize_repo_path(repo_root, file_prop) if file_prop else None
            if normalized:
                norm_key = self._path_key(normalized)
                rel_key = self._path_key(rel_path)
                if (
                    norm_key == rel_key
                    or norm_key.endswith("/" + rel_key)
                    or rel_key.endswith("/" + norm_key)
                ):
                    props = dict(node.get("properties") or {})
                    props["file"] = rel_path
                    node_copy = dict(node)
                    node_copy["properties"] = props
                    nodes.append(node_copy)
                    node_ids.add(node_copy.get("id"))
        if not nodes and not has_file_info:
            return graph_data

        edges = [
            edge for edge in graph_data.get("edges", [])
            if edge.get("source") in node_ids and edge.get("target") in node_ids
        ]
        return {"nodes": nodes, "edges": edges}

    def _extract_archive(self, archive_path: Path, dest_dir: Path) -> None:
        if archive_path.suffix == ".zip":
            with zipfile.ZipFile(archive_path, "r") as zf:
                zf.extractall(dest_dir)
            return
        if archive_path.suffix in (".gz", ".tgz") or archive_path.name.endswith(".tar.gz"):
            with tarfile.open(archive_path, "r:gz") as tf:
                tf.extractall(dest_dir)
            return
        if archive_path.suffix == ".tar":
            with tarfile.open(archive_path, "r:") as tf:
                tf.extractall(dest_dir)
            return
        raise ValueError("Unsupported archive format")

    def _clone_repo(self, url: str, branch: str, token: Optional[str], dest_dir: Path) -> None:
        clone_url = url
        if token and url.startswith("https://"):
            clone_url = url.replace("https://", f"https://{token}@", 1)
        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"

        # Try the requested branch, then fall back to main/master automatically
        fallback = "master" if branch == "main" else "main"
        for attempt_branch in [branch, fallback]:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", "--branch", attempt_branch, clone_url, str(dest_dir)],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if result.returncode == 0:
                return
            # Clean up partial clone before retrying
            if dest_dir.exists():
                import shutil
                shutil.rmtree(dest_dir)

        raise subprocess.CalledProcessError(result.returncode, result.args, result.stderr)

    async def _append_logs(self, scan_id: str, logs: list[str]) -> None:
        if not logs:
            return
        await self.db.scans.update_one(
            {"scan_id": scan_id},
            {
                "$push": {"logs": {"$each": logs}},
                "$set": {"updated_at": datetime.utcnow()},
            },
        )

    async def _update_scan(self, scan_id: str, updates: Dict[str, Any], logs: Optional[list[str]] = None) -> None:
        update_doc: Dict[str, Any] = {"$set": {**updates, "updated_at": datetime.utcnow()}}
        if logs:
            update_doc["$push"] = {"logs": {"$each": logs}}
        await self.db.scans.update_one({"scan_id": scan_id}, update_doc)

    async def _run_direct_code_scan(
        self,
        scan_id: str,
        code: str,
        language: str,
        filename: Optional[str],
        scan_mode: str,
    ):
        trace_step("Worker: _run_direct_code_scan() (app/services/scan_service.py)")
        start_time = time.time()
        try:
            await self._update_scan(
                scan_id,
                {"state": "RUNNING", "started_at": datetime.utcnow().isoformat(), "progress": 10},
                ["[INFO] Starting direct code scan"],
            )

            ext_map = {
                "python": ".py",
                "javascript": ".js",
                "typescript": ".ts",
                "java": ".java",
                "c": ".c",
                "cpp": ".cpp",
                "go": ".go",
                "php": ".php",
            }
            ext = ext_map.get(language, ".txt")
            if not filename:
                filename = f"code{ext}"

            await self._update_scan(
                scan_id,
                {"current_file": filename, "progress": 25},
                [f"[INFO] Analyzing file: {filename}"],
            )

            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=ext,
                delete=False,
                encoding="utf-8",
            ) as tmp_file:
                tmp_file.write(code)
                tmp_path = tmp_file.name

            try:
                await self._append_logs(scan_id, ["[INFO] Building semantic graph..."])
                pipeline = get_pipeline(PipelineConfig(enable_llm=True))
                trace_step("SemanticPipeline: analyze_code()")
                scan_timeout = int(os.getenv("SCAN_TIMEOUT_SECONDS", "300"))
                try:
                    result = await asyncio.wait_for(
                        pipeline.analyze_code(filename=filename, code=code, language=language),
                        timeout=scan_timeout,
                    )
                except asyncio.TimeoutError:
                    logger.warning(f"[scan:{scan_id}] analyze_code timed out after {scan_timeout}s")
                    from semantic_engine.pipeline import AnalysisResult
                    result = AnalysisResult(
                        filename=filename, language=language,
                        lines_of_code=len(code.split('\n')),
                        analysis_time_seconds=float(scan_timeout),
                        graph_nodes=0, graph_edges=0, rules_executed=0,
                        slices_found=0, vulnerabilities_found=0,
                        vulnerabilities=[], graph_data=None,
                        warnings=["Scan timed out — partial results only"],
                        errors=[], success=False,
                    )

                vulnerabilities = self._dedupe_vulnerabilities(None, result.vulnerabilities)
                by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                for vuln in vulnerabilities:
                    severity = vuln.get("severity", "low")
                    by_severity[severity] = by_severity.get(severity, 0) + 1

                duration = time.time() - start_time
                summary = {
                    "scan_id": scan_id,
                    "status": "COMPLETED",
                    "input_type": "DIRECT_CODE",
                    "total_files": 1,
                    "files_scanned": 1,
                    "vulnerabilities_found": len(vulnerabilities),
                    "by_severity": by_severity,
                    "duration_seconds": round(duration, 2),
                    "created_at": datetime.utcnow().isoformat(),
                    "completed_at": datetime.utcnow().isoformat(),
                    "vulnerabilities": vulnerabilities,
                }

                await self._update_scan(
                    scan_id,
                    {
                        "state": "COMPLETED",
                        "progress": 100,
                        "finished_at": datetime.utcnow().isoformat(),
                        "summary": summary,
                        "vulnerabilities": vulnerabilities,
                        "files_scanned": 1,
                        "total_files": 1,
                        "graph_data": result.graph_data,
                    },
                    [
                        f"[INFO] Graph built: {result.graph_nodes} nodes, {result.graph_edges} edges",
                        f"[INFO] Rules executed: {result.rules_executed}",
                        f"[INFO] Vulnerabilities found: {len(vulnerabilities)}",
                        f"[SUCCESS] Scan completed in {duration:.2f}s",
                    ],
                )
            finally:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
        except Exception as e:
            logger.error(f"Direct code scan failed: {e}", exc_info=True)
            await self._update_scan(
                scan_id,
                {
                    "state": "FAILED",
                    "finished_at": datetime.utcnow().isoformat(),
                    "summary": {"scan_id": scan_id, "status": "FAILED", "error": str(e)},
                },
                [f"[ERROR] Scan failed: {str(e)}"],
            )

    async def _run_repository_scan(
        self,
        scan_id: str,
        repo_id: int,
        branch: str,
        scan_mode: str,
        repo_url: Optional[str],
        repo_provider: Optional[str],
        repo_token: Optional[str],
        file_paths: Optional[list[str]],
    ):
        trace_step("Worker: _run_repository_scan() (app/services/scan_service.py)")
        start_time = time.time()
        temp_root = None
        try:
            await self._update_scan(
                scan_id,
                {"state": "RUNNING", "started_at": datetime.utcnow().isoformat(), "progress": 5},
                ["[INFO] Starting repository scan"],
            )

            await self._append_logs(scan_id, [f"[INFO] Repository ID: {repo_id}", f"[INFO] Branch: {branch}"])

            temp_root = Path(tempfile.mkdtemp(prefix="vulcan-repo-"))
            repo_root = temp_root / "repo"
            if repo_provider == "LOCAL":
                trace_step("Repo source: LOCAL archive extract")
                upload_dir = Path(settings.REPO_STORAGE_DIR) / str(repo_id)
                if not upload_dir.exists():
                    raise ValueError("No uploaded archive found for this repository")
                archives = list(upload_dir.glob("*"))
                if not archives:
                    raise ValueError("No uploaded archive found for this repository")
                archive_path = archives[0]
                await self._append_logs(scan_id, [f"[INFO] Extracting archive: {archive_path.name}"])
                self._extract_archive(archive_path, repo_root)
            elif repo_url:
                trace_step("Repo source: git clone")
                await self._append_logs(scan_id, [f"[INFO] Cloning repository: {repo_url}"])
                self._clone_repo(repo_url, branch, repo_token, repo_root)
            else:
                raise ValueError("Repository URL is missing")

            trace_step("Collecting source files for scan")
            files = self._collect_source_files(repo_root)
            if file_paths:
                allowed = {
                    path.strip().replace("\\", "/").lstrip("./")
                    for path in file_paths
                    if path
                }
                files = [
                    path
                    for path in files
                    if str(path.relative_to(repo_root)).replace("\\", "/") in allowed
                ]
            if not files:
                duration = time.time() - start_time
                summary = {
                    "scan_id": scan_id,
                    "status": "FAILED",
                    "input_type": "REPOSITORY",
                    "total_files": 0,
                    "files_scanned": 0,
                    "vulnerabilities_found": 0,
                    "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                    "duration_seconds": round(duration, 2),
                    "created_at": datetime.utcnow().isoformat(),
                    "completed_at": datetime.utcnow().isoformat(),
                    "error": "No scannable files found for the selected scope.",
                }
                await self._update_scan(
                    scan_id,
                    {
                        "state": "FAILED",
                        "progress": 100,
                        "finished_at": datetime.utcnow().isoformat(),
                        "summary": summary,
                        "vulnerabilities": [],
                        "files_scanned": 0,
                        "total_files": 0,
                        "graph_data": None,
                    },
                    ["[ERROR] No scannable files matched the selected scope."],
                )
                return
            await self._update_scan(scan_id, {"total_files": len(files), "progress": 20})

            # Repository-level analysis (multi-file, interprocedural)
            pipeline = get_pipeline(PipelineConfig(enable_llm=True))
            trace_step("SemanticPipeline: analyze_repository()")
            scan_timeout = int(os.getenv("SCAN_TIMEOUT_SECONDS", "300"))
            try:
                repo_result = await asyncio.wait_for(
                    pipeline.analyze_repository(
                        repo_path=str(repo_root),
                        file_paths=[str(p.relative_to(repo_root)).replace("\\", "/") for p in files],
                    ),
                    timeout=scan_timeout,
                )
            except asyncio.TimeoutError:
                logger.warning(f"[scan:{scan_id}] analyze_repository timed out after {scan_timeout}s — completing with partial results")
                from semantic_engine.pipeline import AnalysisResult
                repo_result = AnalysisResult(
                    filename="repository", language="multi",
                    lines_of_code=0, analysis_time_seconds=float(scan_timeout),
                    graph_nodes=0, graph_edges=0, rules_executed=0,
                    slices_found=0, vulnerabilities_found=0,
                    vulnerabilities=[], graph_data=None,
                    warnings=["Scan timed out — partial results only"],
                    errors=[], success=False,
                )

            rel_paths = [str(p.relative_to(repo_root)).replace("\\", "/") for p in files]
            vulnerabilities: list[dict] = self._dedupe_vulnerabilities(
                repo_root, repo_result.vulnerabilities, rel_paths
            )
            # Normalize vulnerability file paths with suffix matching against repo files
            for vuln in vulnerabilities:
                location = vuln.get("location") or {}
                file_path = location.get("file")
                normalized = self._normalize_repo_path(repo_root, file_path, rel_paths)
                if normalized:
                    location["file"] = normalized
                    vuln["location"] = location
            by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "low")
                by_severity[severity] = by_severity.get(severity, 0) + 1

            # Build per-file graph data for UI (no LLM, graph only)
            graph_files: dict[str, dict] = {}
            file_map: dict[str, str] = {}
            file_order: list[str] = []
            global_graph = repo_result.graph_data or {"nodes": [], "edges": []}

            # Normalize global graph file paths to repo-relative for display
            for node in global_graph.get("nodes", []):
                props = node.get("properties") or {}
                normalized = self._normalize_repo_path(repo_root, props.get("file"), rel_paths)
                if normalized:
                    props["file"] = normalized
                    node["properties"] = props

            for i, file_path in enumerate(files):
                rel_path = str(file_path.relative_to(repo_root)).replace("\\", "/")
                file_id = f"file-{i + 1}"
                file_map[file_id] = rel_path
                file_order.append(file_id)
                await self._update_scan(
                    scan_id,
                    {
                        "current_file": rel_path,
                        "files_scanned": i + 1,
                        "progress": 20 + int((i + 1) / max(len(files), 1) * 70),
                    },
                    [f"[INFO] Preparing graph for {rel_path}..."],
                )
                graph_files[file_id] = self._filter_graph_for_file(global_graph, repo_root, rel_path)

            duration = time.time() - start_time
            summary = {
                "scan_id": scan_id,
                "status": "COMPLETED",
                "input_type": "REPOSITORY",
                "total_files": len(files),
                "files_scanned": len(files),
                "vulnerabilities_found": len(vulnerabilities),
                "by_severity": by_severity,
                "duration_seconds": round(duration, 2),
                "created_at": datetime.utcnow().isoformat(),
                "completed_at": datetime.utcnow().isoformat(),
                "vulnerabilities": vulnerabilities,
                "scanned_files": list(file_map.values()),
            }

            await self._update_scan(
                scan_id,
                {
                    "state": "COMPLETED",
                    "progress": 100,
                    "finished_at": datetime.utcnow().isoformat(),
                    "summary": summary,
                    "vulnerabilities": vulnerabilities,
                    "graph_data": {
                        "files": graph_files,
                        "file_map": file_map,
                        "file_order": file_order,
                        "global": global_graph,
                    },
                    },
                    [f"[SUCCESS] Repository scan completed in {duration:.2f}s"],
                )
        except Exception as e:
            logger.error(f"Repository scan failed: {e}", exc_info=True)
            await self._update_scan(
                scan_id,
                {
                    "state": "FAILED",
                    "finished_at": datetime.utcnow().isoformat(),
                    "summary": {"scan_id": scan_id, "status": "FAILED", "error": str(e)},
                },
                [f"[ERROR] Scan failed: {str(e)}"],
            )
        finally:
            if temp_root:
                shutil.rmtree(temp_root, ignore_errors=True)

    async def status(self, scan_id: str) -> ScanStatusRead:
        scan = await self.db.scans.find_one({"scan_id": scan_id})
        if not scan:
            return ScanStatusRead(
                scan_id=scan_id,
                user_id="",
                state="NOT_FOUND",
                progress=0,
                eta=None,
                started_at=None,
                finished_at=None,
                current_file=None,
                files_scanned=0,
                total_files=0,
            )

        return ScanStatusRead(
            scan_id=scan_id,
            user_id=str(scan.get("user_id")),
            state=scan.get("state", "UNKNOWN"),
            progress=scan.get("progress", 0),
            eta=None,
            started_at=scan.get("started_at"),
            finished_at=scan.get("finished_at"),
            current_file=scan.get("current_file"),
            files_scanned=scan.get("files_scanned", 0),
            total_files=scan.get("total_files", 0),
            created_at=scan.get("created_at"),
            updated_at=scan.get("updated_at"),
        )

    async def logs(self, scan_id: str) -> Dict[str, Any]:
        scan = await self.db.scans.find_one({"scan_id": scan_id}, {"logs": {"$slice": -100}})
        if not scan:
            return {"logs": []}
        return {"logs": scan.get("logs", [])}

    async def summary(self, scan_id: str) -> Optional[ScanSummary]:
        scan = await self.db.scans.find_one({"scan_id": scan_id})
        if not scan:
            return None
        summary = scan.get("summary")
        if not summary:
            return None
        def _to_iso(value):
            return value.isoformat() if isinstance(value, datetime) else value
        vulnerabilities = summary.get("vulnerabilities") or []
        if vulnerabilities:
            repo = PatchRepository(self.db)
            vuln_ids = [v.get("id") for v in vulnerabilities if v.get("id")]
            patches = await repo.list_by_vulnerability_ids(vuln_ids)
            patch_map = {p.get("vulnerability_id"): p for p in patches}
            for vuln in vulnerabilities:
                patch = patch_map.get(vuln.get("id"))
                if patch:
                    validations = patch.get("validations") or []
                    passed = sum(1 for v in validations if v.get("passed"))
                    vuln["patch"] = {
                        "status": patch.get("status"),
                        "confidence": patch.get("confidence"),
                        "validation_summary": f"{passed}/{len(validations)} passed",
                        "patch_id": patch.get("patch_id"),
                    }
                else:
                    vuln["patch"] = {
                        "status": "none",
                        "confidence": None,
                        "validation_summary": "0/0 passed",
                        "patch_id": None,
                    }
        merged = {
            "scan_id": scan_id,
            "user_id": str(scan.get("user_id")),
            "status": summary.get("status", scan.get("state", "UNKNOWN")),
            "input_type": summary.get("input_type", scan.get("input_type")),
            "total_files": summary.get("total_files", scan.get("total_files", 0)),
            "files_scanned": summary.get("files_scanned", scan.get("files_scanned", 0)),
            "vulnerabilities_found": summary.get(
                "vulnerabilities_found",
                len(summary.get("vulnerabilities", []) or []),
            ),
            "by_severity": summary.get("by_severity", {"critical": 0, "high": 0, "medium": 0, "low": 0}),
            "duration_seconds": summary.get("duration_seconds", 0.0),
            "created_at": _to_iso(summary.get("created_at", scan.get("created_at"))),
            "completed_at": _to_iso(summary.get("completed_at", scan.get("finished_at"))),
            "vulnerabilities": vulnerabilities,
        }
        return ScanSummary(**merged)

    async def cancel(self, scan_id: str) -> Dict[str, Any]:
        scan = await self.db.scans.find_one({"scan_id": scan_id})
        if not scan:
            return {"state": "NOT_FOUND"}
        await self._update_scan(
            scan_id,
            {"state": "CANCELLED", "finished_at": datetime.utcnow().isoformat()},
            ["[INFO] Scan cancelled by user"],
        )
        return {"state": "CANCELLED"}

    async def ensure_access(self, scan_id: str, user: dict) -> bool:
        scan = await self.db.scans.find_one({"scan_id": scan_id})
        if not scan:
            return False
        if user.get("role") == UserRole.ADMIN.value:
            return True
        return str(scan.get("user_id")) == user.get("id")
