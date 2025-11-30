from typing import List, Optional
from app.schemas.graph import SemanticGraph
from app.schemas.taint import TaintResult, VulnerabilityCandidate, LLMAnalysisResult
from app.domain.analysis.semantic_graph_builder import SemanticGraphBuilder
from app.domain.analysis.taint_engine import TaintEngine
from app.domain.analysis.slice_extractor import SliceExtractor
from app.domain.analysis.llm_reasoning import LLMReasoning


class AnalysisService:
    """
    Orchestrates the full analysis pipeline:
    1. Build semantic graph
    2. Run taint analysis
    3. Extract code slices
    4. Validate with LLM reasoning
    5. Generate patches
    """
    
    def __init__(self, llm_api_key: Optional[str] = None):
        self.llm_api_key = llm_api_key
    
    def analyze_code(self, code: str, language: str = "python", filename: str = "source.py") -> dict:
        """
        Analyze source code for vulnerabilities.
        
        Returns:
            {
                "graph": SemanticGraph,
                "vulnerabilities": List[dict]
            }
        """
        # Step 1: Build semantic graph
        builder = SemanticGraphBuilder(language=language)
        graph = builder.build(code, filename)
        
        # Step 2: Run taint analysis
        taint_engine = TaintEngine()
        taint_results = taint_engine.analyze(graph)
        
        # Step 3: Analyze each taint flow
        vulnerabilities = []
        slice_extractor = SliceExtractor()
        llm = LLMReasoning(llm_api_key=self.llm_api_key)
        
        for taint in taint_results:
            # Extract code slice
            code_snippet = slice_extractor.extract(taint.flow_path, code)
            
            # Create vulnerability candidate
            candidate = VulnerabilityCandidate(
                flow_path=taint.flow_path,
                code_snippet=code_snippet,
                source_description=self._get_source_description(taint.source_node),
                sink_description=self._get_sink_description(taint.sink_node)
            )
            
            # Validate with LLM reasoning
            analysis = llm.analyze(candidate)
            
            if analysis.is_vulnerability:
                patch = llm.generate_patch(candidate, analysis)
                
                vulnerabilities.append({
                    "source": {
                        "id": taint.source_node.id,
                        "name": taint.source_node.name,
                        "file": taint.source_node.file,
                        "line": taint.source_node.line
                    },
                    "sink": {
                        "id": taint.sink_node.id,
                        "name": taint.sink_node.name,
                        "file": taint.sink_node.file,
                        "line": taint.sink_node.line
                    },
                    "severity": taint.severity,
                    "flow_path": [
                        {"id": n.id, "name": n.name, "line": n.line} 
                        for n in taint.flow_path
                    ],
                    "code_snippet": code_snippet,
                    "explanation": analysis.explanation,
                    "recommended_fix": analysis.recommended_fix,
                    "patch": patch
                })
        
        return {
            "graph": graph.model_dump(),
            "vulnerabilities": vulnerabilities
        }
    
    def get_graph(self, code: str, language: str = "python", filename: str = "source.py") -> SemanticGraph:
        """Build and return just the semantic graph."""
        builder = SemanticGraphBuilder(language=language)
        return builder.build(code, filename)
    
    def _get_source_description(self, node) -> str:
        """Get human-readable source description."""
        return f"User input from {node.name or 'unknown source'}"
    
    def _get_sink_description(self, node) -> str:
        """Get human-readable sink description."""
        return f"Potentially dangerous operation: {node.name or 'unknown sink'}"
