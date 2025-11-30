from app.schemas.graph import SemanticGraph
from app.domain.analysis.ast_parser import ASTParser
from app.domain.analysis.cfg_builder import CFGBuilder
from app.domain.analysis.dfg_builder_enhanced import EnhancedDFGBuilder
from app.domain.analysis.taint_engine import TaintEngine


class SemanticGraphBuilder:
    """
    Orchestrates AST parsing, CFG, and DFG construction
    to produce a unified semantic graph.
    
    Now uses EnhancedDFGBuilder for comprehensive string operation tracking.
    """
    
    def __init__(self, language: str = "python"):
        self.language = language
        self.ast_parser = ASTParser(language=language)
        self.cfg_builder = CFGBuilder()
        self.dfg_builder = EnhancedDFGBuilder()  # Using enhanced version
        self.taint_engine = TaintEngine()  # Add taint analysis
    
    def build(self, code: str, filename: str = "source.py") -> SemanticGraph:
        """
        Build complete semantic graph from source code.
        
        Steps:
        1. Parse AST
        2. Build CFG
        3. Build DFG (with enhanced string operation tracking)
        4. Return unified graph
        """
        # Step 1: Parse AST
        graph = self.ast_parser.parse(code, filename)
        
        # Step 2: Add CFG edges
        graph = self.cfg_builder.build(graph)
        
        # Step 3: Add DFG edges (enhanced with f-string/concat/format tracking)
        graph = self.dfg_builder.build(graph, code, filename)
        
        return graph
