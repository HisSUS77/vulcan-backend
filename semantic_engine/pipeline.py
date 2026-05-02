"""
Semantic Analysis Pipeline - End-to-End Vulnerability Detection
Orchestrates: AST → CFG → DFG → Unified CPG → Query Execution → LLM Classification → Exploit PoC
Production-grade security scanning with guardrails and error handling.
"""
import asyncio
import os
import time
import logging
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path

from app.schemas.graph import SemanticGraph
from app.domain.analysis.semantic_graph_builder import SemanticGraphBuilder

from semantic_engine.query_store.loader import get_query_store, QueryRule
from semantic_engine.query_executor.executor import QueryExecutor, CodeSlice
from semantic_engine.classifier.classifier import get_classifier, ClassifiedVulnerability
from app.core.trace import trace_step

logger = logging.getLogger(__name__)


@dataclass
class PipelineConfig:
    """Configuration for semantic analysis pipeline."""
    enable_llm: Optional[bool] = None  # None means: read from env
    enable_exploit: bool = True        # set False to skip PoC exploit generation (e.g. benchmark)
    max_graph_nodes: int = 200_000
    max_path_length: int = 50
    max_paths_per_rule: int = 100
    query_timeout: int = 30  # seconds per query
    llm_timeout: int = 15  # seconds per LLM call
    enable_cycle_detection: bool = True
    enable_path_discovery: bool = True
    path_score_threshold: float = 0.35
    max_candidate_paths: int = 200
    
    def __post_init__(self):
        """Load enable_llm from environment if not explicitly set."""
        if self.enable_llm is None:
            env_enable = os.getenv('ENABLE_LLM', 'true').lower()
            if env_enable in ['true', '1', 'yes']:
                self.enable_llm = True
            elif env_enable in ['false', '0', 'no']:
                self.enable_llm = False
            else:
                self.enable_llm = True


@dataclass
class AnalysisResult:
    """
    Complete analysis result with vulnerabilities and metadata.
    """
    # Input metadata
    filename: str
    language: str
    lines_of_code: int
    
    # Analysis metrics
    analysis_time_seconds: float
    graph_nodes: int
    graph_edges: int
    rules_executed: int
    slices_found: int
    vulnerabilities_found: int
    
    # Vulnerabilities (sorted by severity)
    vulnerabilities: List[Dict[str, Any]]
    
    # Warnings/errors
    warnings: List[str]
    errors: List[str]
    
    # Success status
    success: bool
    
    # Graph data for visualization (AST/CFG/DFG/CPG) - optional, has default
    graph_data: Optional[Dict[str, Any]] = None


class SemanticPipeline:
    """
    End-to-end semantic vulnerability analysis pipeline.
    Combines static analysis with LLM-powered classification.
    """
    
    def __init__(self, config: Optional[PipelineConfig] = None):
        """
        Initialize pipeline with configuration.
        
        Args:
            config: Pipeline configuration (uses defaults if None)
        """
        self.config = config or PipelineConfig()
        
        # Initialize components
        self.query_store = get_query_store()
        self.query_executor = QueryExecutor(
            max_path_length=self.config.max_path_length,
            max_paths_per_rule=self.config.max_paths_per_rule
        )
        self.classifier = get_classifier(enable_llm=self.config.enable_llm)
        
        logger.info(f"SemanticPipeline initialized (LLM: {self.config.enable_llm})")
    
    async def analyze_code(
        self,
        filename: str,
        code: str,
        language: str = "python"
    ) -> AnalysisResult:
        trace_step("Pipeline: analyze_code() (semantic_engine/pipeline.py)")
        """
        Analyze code for security vulnerabilities.
        
        Args:
            filename: Name of file being analyzed
            code: Source code content
            language: Programming language ('python', 'javascript', etc.)
        
        Returns:
            AnalysisResult with detected vulnerabilities
        """
        start_time = time.time()
        warnings = []
        errors = []
        
        logger.info(f"Starting analysis: {filename} ({language})")
        
        try:
            # Step 1: Build semantic graph
            trace_step("Pipeline step: _build_graph()")
            graph = await self._build_graph(code, language)
            
            if graph is None:
                return self._create_error_result(
                    filename, language, code,
                    ["Failed to build semantic graph"],
                    ["Graph construction failed"]
                )
            
            # Check graph size limits
            if len(graph.nodes) > self.config.max_graph_nodes:
                error_msg = f"Graph too large: {len(graph.nodes)} nodes (limit: {self.config.max_graph_nodes})"
                logger.error(error_msg)
                return self._create_error_result(
                    filename, language, code,
                    warnings, [error_msg]
                )
            
            logger.info(f"Graph built: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
            
            # Step 2: Broad path discovery (primary)
            all_slices = []
            if self.config.enable_path_discovery:
                trace_step("Pipeline step: _discover_paths()")
                discovery_slices = await self._discover_paths(graph, {filename: code})
                all_slices.extend(discovery_slices)
                logger.info(f"Path discovery: {len(discovery_slices)} candidate slices found")

            # Step 3: Execute security queries (augment discovery results)
            trace_step("Pipeline step: _execute_queries()")
            query_slices = await self._execute_queries(graph, code)
            if discovery_slices:
                discovery_slices = self._filter_discovery_slices(discovery_slices, query_slices)
            all_slices = (discovery_slices or []) + query_slices
            logger.info(f"Query execution: {len(query_slices)} slices found")
            
            # Step 4: Classify with LLM
            trace_step("Pipeline step: _classify_slices()")
            vulnerabilities = await self._classify_slices(all_slices)
            vulnerabilities = self._dedupe_vulnerabilities(vulnerabilities)
            logger.info(f"Classification: {len(vulnerabilities)} vulnerabilities confirmed")

            # Step 5: Enrich HIGH/CRITICAL confirmed vulns with PoC exploits (parallel)
            formatted_vulns = [self._format_vulnerability(v) for v in vulnerabilities]
            formatted_vulns = await self._enrich_with_exploits(formatted_vulns)

            # Step 6: Build result
            analysis_time = time.time() - start_time
            graph_data    = self._serialize_graph(graph)

            result = AnalysisResult(
                filename=filename,
                language=language,
                lines_of_code=len(code.split('\n')),
                analysis_time_seconds=round(analysis_time, 2),
                graph_nodes=len(graph.nodes),
                graph_edges=len(graph.edges),
                rules_executed=len(self.query_store.get_all_queries()),
                slices_found=len(all_slices),
                vulnerabilities_found=len(vulnerabilities),
                vulnerabilities=formatted_vulns,
                graph_data=graph_data,
                warnings=warnings,
                errors=errors,
                success=True
            )
            
            logger.info(f"Analysis complete: {len(vulnerabilities)} vulnerabilities in {analysis_time:.2f}s")
            return result
        
        except Exception as e:
            logger.error(f"Analysis failed: {e}", exc_info=True)
            return self._create_error_result(
                filename, language, code,
                warnings, [str(e)]
            )
    
    async def _build_graph(self, code: str, language: str) -> Optional[SemanticGraph]:
        """
        Build unified semantic graph from source code.
        
        Args:
            code: Source code
            language: Programming language
        
        Returns:
            SemanticGraph or None on failure
        """
        try:
            _SUPPORTED = {'python', 'py', 'javascript', 'js', 'jsx', 'typescript', 'ts', 'tsx'}
            if language.lower() not in _SUPPORTED:
                logger.warning(f"Unsupported language: {language}, using Python parser")

            # Build semantic graph using existing components
            builder = SemanticGraphBuilder(language=language)
            graph = builder.build(code, filename="input")
            
            # Validate graph
            if not graph or not graph.nodes:
                logger.error("Empty graph generated")
                return None
            
            # Cycle detection (optional)
            if self.config.enable_cycle_detection:
                has_cycles = self._detect_cycles(graph)
                if has_cycles:
                    logger.debug("Cycles detected in graph (may affect path finding)")
            
            return graph
        
        except Exception as e:
            logger.error(f"Graph building failed: {e}")
            return None
    
    async def _execute_queries(
        self,
        graph: SemanticGraph,
        source_code: str,
        source_code_map: Optional[Dict[str, str]] = None
    ) -> List[CodeSlice]:
        """
        Execute all security queries against graph.
        
        Args:
            graph: Unified semantic graph
            source_code: Original source code
        
        Returns:
            List of detected code slices
        """
        all_slices = []
        queries = self.query_store.get_all_queries()
        
        for query in queries:
            try:
                slices = self.query_executor.execute_query(
                    graph, query, source_code, source_code_map
                )
                all_slices.extend(slices)
            except Exception as e:
                logger.error(f"Query {query.rule_id} failed: {e}")
                continue
        
        return all_slices

    # Runs PathDiscovery to find broad source→sink path candidates across the graph
    async def _discover_paths(
        self,
        graph: SemanticGraph,
        source_code_map: Dict[str, str]
    ) -> List[CodeSlice]:
        from semantic_engine.path_discovery import PathDiscovery
        discovery = PathDiscovery(
            max_depth=self.config.max_path_length,
            max_candidates=self.config.max_candidate_paths,
            score_threshold=self.config.path_score_threshold
        )
        return discovery.discover(graph, source_code_map, self.query_store)

    async def analyze_repository(
        self,
        repo_path: str,
        file_paths: Optional[list[str]] = None
    ) -> AnalysisResult:
        trace_step("Pipeline: analyze_repository() (semantic_engine/pipeline.py)")
        """
        Analyze a repository with multi-file, interprocedural path discovery.
        """
        start_time = time.time()
        warnings = []
        errors = []
        try:
            from app.domain.analysis.multi_file_repo_graph import MultiFileRepositoryGraph
            trace_step("Repo graph: MultiFileRepositoryGraph.build()")
            allowed = set((p or "").replace("\\", "/") for p in (file_paths or []))
            repo_graph = MultiFileRepositoryGraph(
                repo_path,
                allowed_files=allowed if allowed else None,
            )
            result = repo_graph.build()
            graph = result["global_cpg"]

            # Reload queries in case queries.json changed since startup
            self.query_store.reload()

            # Filter source map by selected files if provided
            source_code_map: Dict[str, str] = {}
            repo_root_resolved = Path(repo_path).resolve()
            for module in result["modules"]:
                file_path = module.file_path
                # Compute repo-relative path for allowed-set comparison
                try:
                    repo_rel = str(Path(file_path).resolve().relative_to(repo_root_resolved))
                    repo_rel = repo_rel.replace("\\", "/")
                except Exception:
                    repo_rel = file_path.replace("\\", "/")

                if allowed and repo_rel not in allowed:
                    continue
                try:
                    code = Path(file_path).read_text(encoding="utf-8", errors="ignore")
                    # Store under multiple keys for flexible lookup
                    source_code_map[file_path] = code
                    source_code_map[repo_rel] = code
                    abs_path = str(Path(file_path).resolve())
                    source_code_map[abs_path] = code
                except Exception:
                    continue

            # Add dependency manifests for A06 (Vulnerable & Outdated Components)
            self._add_dependency_files(repo_path, source_code_map, allowed)

            # Broad path discovery
            all_slices = []
            if self.config.enable_path_discovery:
                trace_step("Pipeline step: _discover_paths() [repo]")
                discovery_slices = await self._discover_paths(graph, source_code_map)
                logger.info(f"Path discovery: {len(discovery_slices)} candidate slices found")

            # Always augment with rule-based queries (use concatenated source if needed)
            concat_source = "\n".join(source_code_map.values()) if source_code_map else ""
            trace_step("Pipeline step: _execute_queries() [repo]")
            query_slices = await self._execute_queries(graph, concat_source, source_code_map)
            if discovery_slices:
                discovery_slices = self._filter_discovery_slices(discovery_slices, query_slices)
            all_slices = (discovery_slices or []) + query_slices
            logger.info(f"Query execution: {len(query_slices)} slices found")

            trace_step("Pipeline step: _classify_slices() [repo]")
            vulnerabilities = await self._classify_slices(all_slices)
            vulnerabilities = self._dedupe_vulnerabilities(vulnerabilities)

            # Enrich HIGH/CRITICAL confirmed vulns with PoC exploits (parallel)
            formatted_vulns = [self._format_vulnerability(v) for v in vulnerabilities]
            formatted_vulns = await self._enrich_with_exploits(formatted_vulns)

            analysis_time = time.time() - start_time
            graph_data    = self._serialize_graph(graph)
            return AnalysisResult(
                filename="repository",
                language="multi",
                lines_of_code=sum(len(code.splitlines()) for code in source_code_map.values()),
                analysis_time_seconds=round(analysis_time, 2),
                graph_nodes=len(graph.nodes),
                graph_edges=len(graph.edges),
                rules_executed=len(self.query_store.get_all_queries()),
                slices_found=len(all_slices),
                vulnerabilities_found=len(vulnerabilities),
                vulnerabilities=formatted_vulns,
                graph_data=graph_data,
                warnings=warnings,
                errors=errors,
                success=True
            )
        except Exception as e:
            logger.error(f"Repository analysis failed: {e}", exc_info=True)
            return self._create_error_result(
                "repository", "multi", "", warnings, [str(e)]
            )

    def _add_dependency_files(
        self,
        repo_path: str,
        source_code_map: Dict[str, str],
        allowed: set
    ) -> None:
        """Add dependency manifests/locks to source map for regex-based rules."""
        repo_root = Path(repo_path)
        file_names = {
            "requirements.txt",
            "requirements-dev.txt",
            "pipfile",
            "pipfile.lock",
            "pyproject.toml",
            "poetry.lock",
            "setup.cfg",
            ".npmrc",
            "package.json",
            "package-lock.json",
            "npm-shrinkwrap.json",
            "yarn.lock",
            "pnpm-lock.yaml"
        }
        exclude_dirs = {"node_modules", "venv", ".venv", ".git", "__pycache__", "dist", "build"}

        for path in repo_root.rglob("*"):
            if not path.is_file():
                continue
            if path.name.lower() not in file_names:
                continue
            if any(part in exclude_dirs for part in path.parts):
                continue

            rel_path = str(path.relative_to(repo_root)).replace("\\", "/")
            # Config/manifest files are always included for A06 rules —
            # do NOT filter them by the source-file allowed set.
            try:
                code = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            abs_path = str(path)
            source_code_map.setdefault(abs_path, code)
            source_code_map.setdefault(rel_path, code)

    def build_graph_data(
        self,
        code: str,
        language: str = "python",
        filename: str = "input"
    ) -> Optional[Dict[str, Any]]:
        """Build and serialize graph data without running queries/LLM."""
        try:
            builder = SemanticGraphBuilder(language=language)
            graph = builder.build(code, filename=filename)
            return self._serialize_graph(graph)
        except Exception:
            return None
    
    async def _classify_slices(
        self, slices: List[CodeSlice]
    ) -> List[ClassifiedVulnerability]:
        """
        Classify code slices using LLM.
        
        Args:
            slices: List of code slices
        
        Returns:
            List of classified vulnerabilities (filtered for true positives)
        """
        return await self.classifier.classify_slices(slices)

    def _filter_discovery_slices(
        self,
        discovery_slices: List[CodeSlice],
        query_slices: List[CodeSlice]
    ) -> List[CodeSlice]:
        """
        Remove discovery slices that are already covered by rule-based slices.
        """
        covered = set()
        for s in query_slices:
            loc = s.location or {}
            covered.add((
                loc.get("file"),
                loc.get("start_line"),
                loc.get("end_line"),
                s.sink_label
            ))

        filtered = []
        for s in discovery_slices:
            loc = s.location or {}
            key = (
                loc.get("file"),
                loc.get("start_line"),
                loc.get("end_line"),
                s.sink_label
            )
            if key in covered:
                continue
            filtered.append(s)
        return filtered

    def _dedupe_vulnerabilities(
        self,
        vulnerabilities: List[ClassifiedVulnerability]
    ) -> List[ClassifiedVulnerability]:
        """
        Collapse duplicate findings that point to the same rule + sink at the same location.
        Keep the most "sure" finding while avoiding noisy duplicates.
        """
        if not vulnerabilities:
            return vulnerabilities

        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

        def rank(v: ClassifiedVulnerability) -> tuple:
            sev = severity_rank.get((v.final_severity or "").lower(), 0)
            conf = v.final_confidence or 0.0
            llm_value = getattr(v.llm_classification, "value", v.llm_classification)
            if llm_value == "VULNERABLE":
                strength = 2
            elif llm_value == "LIKELY_VULNERABLE":
                strength = 1
            else:
                strength = 0
            has_snippet = 1 if (v.code_snippet or "").strip() else 0
            path_len = len(v.path_nodes or [])
            return (strength, has_snippet, conf, sev, -path_len)

        best_by_key: dict[tuple, ClassifiedVulnerability] = {}
        for v in vulnerabilities:
            loc = v.location or {}
            key = (
                v.rule_name,
                loc.get("file"),
                loc.get("start_line"),
                loc.get("end_line"),
                v.sink_label,
            )
            existing = best_by_key.get(key)
            if existing is None or rank(v) > rank(existing):
                best_by_key[key] = v

        return list(best_by_key.values())
    
    def _detect_cycles(self, graph: SemanticGraph) -> bool:
        """
        Detect cycles in graph using DFS.
        
        Args:
            graph: Semantic graph
        
        Returns:
            True if cycles detected
        """
        # Build adjacency list
        adj = {}
        for edge in graph.edges:
            if edge.from_node not in adj:
                adj[edge.from_node] = []
            adj[edge.from_node].append(edge.to_node)
        
        # DFS cycle detection
        visited = set()
        rec_stack = set()
        
        def has_cycle(node):
            visited.add(node)
            rec_stack.add(node)
            
            for neighbor in adj.get(node, []):
                if neighbor not in visited:
                    if has_cycle(neighbor):
                        return True
                elif neighbor in rec_stack:
                    return True
            
            rec_stack.remove(node)
            return False
        
        for node in graph.nodes:
            if node.id not in visited:
                if has_cycle(node.id):
                    return True
        
        return False
    
    def _serialize_graph(self, graph) -> Dict[str, Any]:
        """
        Serialize semantic graph to JSON-serializable format.
        
        Args:
            graph: SemanticGraph object
        
        Returns:
            Dictionary with nodes and edges
        """
        nodes = []
        for node in graph.nodes:
            metadata = node.metadata if node.metadata else {}
            nodes.append({
                "id": node.id,
                "label": node.name or str(node.type),
                "type": str(node.type),
                "node_type": getattr(metadata, 'graph_type', 'AST') if hasattr(metadata, 'graph_type') else 'AST',
                "properties": {
                    "file": node.file,
                    "line": node.line,
                    "column": node.column,
                    "value": str(node.value) if node.value is not None else None
                }
            })
        
        edges = []
        for edge in graph.edges:
            edge_metadata = edge.metadata if edge.metadata else {}
            edges.append({
                "source": edge.from_node,
                "target": edge.to_node,
                "type": str(edge.type),
                "edge_type": edge_metadata.get('graph_type', 'CHILD') if isinstance(edge_metadata, dict) else 'CHILD',
                "label": str(edge.type),
                "properties": edge_metadata if isinstance(edge_metadata, dict) else {}
            })
        
        return {
            "nodes": nodes,
            "edges": edges
        }
    
    async def _enrich_with_exploits(self, formatted_vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Attach PoC exploit data to HIGH/CRITICAL VULNERABLE findings.
        Processed sequentially — the LLM pool is rate-limited so concurrent
        calls just pile up on the throttle lock and cause repeated retries.
        Non-blocking: any failure leaves the finding unchanged.
        """
        if not self.config.enable_exploit:
            return formatted_vulns
        try:
            from semantic_engine.classifier.exploit_llm_service import get_exploit_service
            exploit_svc = get_exploit_service()
            if not exploit_svc.is_available:
                return formatted_vulns

            eligible: list[int] = []
            for i, fmt in enumerate(formatted_vulns):
                sev     = (fmt.get("severity") or "").lower()
                llm_cls = fmt.get("analysis", {}).get("llm_classification", {}).get("classification", "")
                if sev in ("high", "critical") and llm_cls in ("VULNERABLE", "LIKELY_VULNERABLE"):
                    eligible.append(i)

            if not eligible:
                return formatted_vulns

            # Cap at 5 findings to bound total exploit-generation time
            eligible = eligible[:5]
            logger.info(f"Generating PoC exploits for {len(eligible)} HIGH/CRITICAL finding(s) (sequential)...")
            for i in eligible:
                fmt = formatted_vulns[i]
                try:
                    result = await exploit_svc.generate_exploit(
                        code_snippet=fmt.get("evidence", {}).get("code_snippet", "") or "",
                        vuln_type=fmt.get("type", "Unknown"),
                        cwe=fmt.get("cwe"),
                        owasp=fmt.get("owasp"),
                        severity=(fmt.get("severity") or "").lower(),
                        file_path=fmt.get("location", {}).get("file", ""),
                    )
                    if result is not None:
                        formatted_vulns[i]["exploit"] = {
                            "exploitable":   result.exploitable,
                            "exploit_type":  result.exploit_type,
                            "attack_vector": result.attack_vector,
                            "poc_code":      result.poc_code,
                            "impact":        result.impact,
                            "bypass_hints":  result.bypass_hints,
                            "confidence":    round(result.confidence, 2),
                        }
                except Exception as exc:
                    logger.warning(f"Exploit generation failed for finding {i} (skipping): {exc}")

        except Exception as exc:
            logger.warning(f"Exploit enrichment failed (non-blocking): {exc}")

        return formatted_vulns

    @staticmethod
    def _compute_cvss_score(severity: str, exploitability: float) -> float:
        """
        Approximate CVSS v3.1 Base Score from severity band + exploitability.
        Maps: critical 9.0-10.0, high 7.0-8.9, medium 4.0-6.9, low 0.1-3.9
        """
        bands = {
            "critical": (9.0, 10.0),
            "high":     (7.0,  8.9),
            "medium":   (4.0,  6.9),
            "low":      (0.1,  3.9),
        }
        lo, hi = bands.get((severity or "").lower(), (4.0, 6.9))
        score = lo + (hi - lo) * max(0.0, min(1.0, exploitability))
        return round(score, 1)

    def _format_vulnerability(self, vuln: ClassifiedVulnerability) -> Dict[str, Any]:
        """
        Format vulnerability for API response.

        Args:
            vuln: Classified vulnerability

        Returns:
            Dictionary representation
        """
        cvss_score = self._compute_cvss_score(vuln.final_severity, vuln.llm_exploitability)
        return {
            "id": vuln.slice_id,
            "type": vuln.rule_name,
            "severity": vuln.final_severity,
            "confidence": round(vuln.final_confidence, 2),
            "cvss_score": cvss_score,
            "owasp": vuln.owasp,
            "cwe": vuln.cwe,

            "location": {
                "file": vuln.location.get("file", "unknown"),
                "start_line": vuln.location.get("start_line", 0),
                "end_line": vuln.location.get("end_line", 0)
            },

            "evidence": {
                "source": vuln.source_label,
                "sink": vuln.sink_label,
                "pattern": vuln.pattern_type,
                "code_snippet": vuln.code_snippet,
                "data_flow_path": vuln.path_nodes
            },

            "analysis": {
                "static_detection": {
                    "severity": vuln.static_severity,
                    "confidence": vuln.static_confidence,
                    "reason": vuln.static_reason
                },
                "llm_classification": {
                    "classification": vuln.llm_classification.value,
                    "severity": vuln.llm_severity,
                    "exploitability": round(vuln.llm_exploitability, 2),
                    "confidence": round(vuln.llm_confidence, 2),
                    "explanation": vuln.llm_explanation,
                    "remediation": vuln.llm_remediation
                }
            }
        }
    
    def _create_error_result(
        self,
        filename: str,
        language: str,
        code: str,
        warnings: List[str],
        errors: List[str]
    ) -> AnalysisResult:
        """Create error result when analysis fails."""
        return AnalysisResult(
            filename=filename,
            language=language,
            lines_of_code=len(code.split('\n')),
            analysis_time_seconds=0.0,
            graph_nodes=0,
            graph_edges=0,
            rules_executed=0,
            slices_found=0,
            vulnerabilities_found=0,
            vulnerabilities=[],
            warnings=warnings,
            errors=errors,
            success=False
        )


# Global pipeline instance
_pipeline_instance: Optional[SemanticPipeline] = None


def get_pipeline(config: Optional[PipelineConfig] = None) -> SemanticPipeline:
    """
    Get global pipeline instance (singleton).
    
    Args:
        config: Pipeline configuration (only used on first call)
    
    Returns:
        SemanticPipeline instance
    """
    global _pipeline_instance
    
    if _pipeline_instance is None:
        _pipeline_instance = SemanticPipeline(config)
    elif config is not None:
        if (_pipeline_instance.config.enable_llm != config.enable_llm or
                _pipeline_instance.config.enable_exploit != config.enable_exploit):
            _pipeline_instance = SemanticPipeline(config)
    
    return _pipeline_instance
