"""
Semantic Analysis Pipeline - End-to-End Vulnerability Detection
Orchestrates: AST → CFG → DFG → Unified CPG → Query Execution → LLM Classification
Production-grade security scanning with guardrails and error handling.
"""
import os
import time
import logging
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict

from app.schemas.graph import SemanticGraph
from app.domain.analysis.ast_parser import ASTParser
from app.domain.analysis.cfg_builder import CFGBuilder
from app.domain.analysis.dfg_builder import DFGBuilder
from app.domain.analysis.semantic_graph_builder import SemanticGraphBuilder

from semantic_engine.query_store.loader import get_query_store, QueryRule
from semantic_engine.query_executor.executor import QueryExecutor, CodeSlice
from semantic_engine.classifier.classifier import get_classifier, ClassifiedVulnerability

logger = logging.getLogger(__name__)


@dataclass
class PipelineConfig:
    """Configuration for semantic analysis pipeline."""
    enable_llm: bool = True  # LLM enabled by default
    max_graph_nodes: int = 200_000
    max_path_length: int = 50
    max_paths_per_rule: int = 100
    query_timeout: int = 30  # seconds per query
    llm_timeout: int = 15  # seconds per LLM call
    enable_cycle_detection: bool = True
    
    def __post_init__(self):
        """Load enable_llm from environment if not explicitly set."""
        env_enable = os.getenv('ENABLE_LLM', 'true').lower()
        if env_enable in ['true', '1', 'yes']:
            self.enable_llm = True
        elif env_enable in ['false', '0', 'no']:
            self.enable_llm = False


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
            
            # Step 2: Execute security queries
            all_slices = await self._execute_queries(graph, code)
            logger.info(f"Query execution: {len(all_slices)} slices found")
            
            # Step 3: Classify with LLM
            vulnerabilities = await self._classify_slices(all_slices)
            logger.info(f"Classification: {len(vulnerabilities)} vulnerabilities confirmed")
            
            # Step 4: Build result
            analysis_time = time.time() - start_time
            
            # Serialize graph for visualization
            graph_data = self._serialize_graph(graph)
            
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
                vulnerabilities=[self._format_vulnerability(v) for v in vulnerabilities],
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
            if language.lower() not in ['python', 'py']:
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
                    logger.warning("Cycles detected in graph (may affect path finding)")
            
            return graph
        
        except Exception as e:
            logger.error(f"Graph building failed: {e}")
            return None
    
    async def _execute_queries(
        self, graph: SemanticGraph, source_code: str
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
                    graph, query, source_code
                )
                all_slices.extend(slices)
            except Exception as e:
                logger.error(f"Query {query.rule_id} failed: {e}")
                continue
        
        return all_slices
    
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
    
    def _format_vulnerability(self, vuln: ClassifiedVulnerability) -> Dict[str, Any]:
        """
        Format vulnerability for API response.
        
        Args:
            vuln: Classified vulnerability
        
        Returns:
            Dictionary representation
        """
        return {
            "id": vuln.slice_id,
            "type": vuln.rule_name,
            "severity": vuln.final_severity,
            "confidence": round(vuln.final_confidence, 2),
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
                "data_flow_path": vuln.path_nodes  # Complete taint flow path for visualization
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
    
    return _pipeline_instance
