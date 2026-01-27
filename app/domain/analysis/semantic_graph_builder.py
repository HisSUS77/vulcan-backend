"""
Semantic Graph Builder - NEW ARCHITECTURE
==========================================

Uses tree-sitter based CPG parser + interprocedural DFG builder

Architecture:
1. CPG Parser (tree-sitter) - AST extraction with full language support
2. Interprocedural DFG - Data flow across function boundaries
3. Taint Engine - Vulnerability detection

MIGRATION NOTE:
Old components (ast_parser_enhanced, cfg_builder, dfg_builder) have been
removed in favor of the new CPG parser + interprocedural DFG approach.
"""

from app.schemas.graph import SemanticGraph, GraphNode, GraphEdge
from app.domain.analysis.cpg_parser import CPGParser
from app.domain.analysis.interprocedural_dfg import InterproceduralDFG
from app.domain.analysis.taint_engine import TaintEngine
from app.enums.node_type import NodeType
from app.enums.edge_type import EdgeType


class SemanticGraphBuilder:
    """
    Orchestrates CPG parsing and interprocedural DFG construction
    to produce a unified semantic graph.
    
    NEW ARCHITECTURE:
    - Uses tree-sitter based CPG parser (supports Python, JS, TS, and more)
    - Interprocedural DFG with closure/callback/tuple unpacking support
    - Maintains backward compatibility with SemanticGraph schema
    """
    
    def __init__(self, language: str = "python"):
        self.language = language
        self.cpg_parser = CPGParser()
        self.taint_engine = TaintEngine()
    
    def build(self, code: str, filename: str = "source.py") -> SemanticGraph:
        """
        Build complete semantic graph from source code.
        
        Steps:
        1. Parse CPG with tree-sitter
        2. Build interprocedural DFG
        3. Run taint analysis
        4. Convert to SemanticGraph format (backward compatibility)
        
        Args:
            code: Source code to analyze
            filename: Filename for context
        
        Returns:
            SemanticGraph with nodes, edges, and analysis results
        """
        # Step 1: Parse CPG
        cpg = self.cpg_parser.parse_code(code, self.language, filename)
        
        # Step 2: Build interprocedural DFG
        dfg_builder = InterproceduralDFG(cpg)
        enhanced_cpg = dfg_builder.build()
        
        # Step 3: Convert CPG to SemanticGraph (for backward compatibility)
        semantic_graph = self._cpg_to_semantic_graph(enhanced_cpg)
        
        return semantic_graph
    
    def _cpg_to_semantic_graph(self, cpg) -> SemanticGraph:
        """
        Convert CPG to SemanticGraph format for backward compatibility
        
        Maps:
        - CPGNode -> GraphNode
        - CPGEdge -> GraphEdge
        - Preserves all metadata
        """
        nodes = []
        edges = []
        
        # Convert nodes
        for cpg_node in cpg.nodes:
            # Map CPG node type to legacy NodeType
            node_type = self._map_node_type(cpg_node.node_type)
            
            graph_node = GraphNode(
                id=cpg_node.id,
                type=node_type,
                name=cpg_node.name or "",
                code=cpg_node.code or "",
                file=cpg_node.file,
                line=cpg_node.line_start,
                column=cpg_node.column_start,
                metadata={
                    "node_type": cpg_node.node_type,
                    "language": cpg_node.language,
                    "line_end": cpg_node.line_end,
                    "column_end": cpg_node.column_end,
                    "scope_id": cpg_node.scope_id,
                    "is_async": getattr(cpg_node, "is_async", False),
                }
            )
            nodes.append(graph_node)
        
        # Convert edges
        for cpg_edge in cpg.edges:
            # Map CPG edge type to legacy EdgeType
            edge_type = self._map_edge_type(cpg_edge.edge_type)
            
            graph_edge = GraphEdge(
                source=cpg_edge.source,
                target=cpg_edge.target,
                type=edge_type,
                metadata=cpg_edge.metadata or {}
            )
            edges.append(graph_edge)
        
        return SemanticGraph(nodes=nodes, edges=edges)
    
    def _map_node_type(self, cpg_type: str) -> NodeType:
        """Map CPG node type to legacy NodeType enum"""
        type_mapping = {
            "FUNCTION": NodeType.FUNCTION,
            "ASYNC_FUNCTION": NodeType.ASYNC_FUNCTION,
            "METHOD": NodeType.METHOD,
            "CLASS": NodeType.CLASS,
            "CALL": NodeType.CALL,
            "CALL_EXPRESSION": NodeType.CALL,
            "IDENTIFIER": NodeType.IDENTIFIER,
            "VARIABLE_DECLARATION": NodeType.VARIABLE,
            "PARAMETER": NodeType.PARAMETER,
            "RETURN": NodeType.RETURN_STMT,
            "RETURN_STATEMENT": NodeType.RETURN_STMT,
            "IF_STATEMENT": NodeType.IF_STMT,
            "FOR_STATEMENT": NodeType.FOR_STMT,
            "WHILE_STATEMENT": NodeType.WHILE_STMT,
            "TRY_STATEMENT": NodeType.TRY_STMT,
            "IMPORT": NodeType.IMPORT,
            "EXPRESSION": NodeType.EXPRESSION,
            "ASSIGNMENT": NodeType.ASSIGNMENT,
            "BINARY_EXPRESSION": NodeType.BINARY_OP,
            "STRING": NodeType.LITERAL,
            "NUMBER": NodeType.LITERAL,
        }
        
        return type_mapping.get(cpg_type, NodeType.UNKNOWN)
    
    def _map_edge_type(self, cpg_edge_type: str) -> EdgeType:
        """Map CPG edge type to legacy EdgeType enum"""
        type_mapping = {
            "AST_CHILD": EdgeType.AST,
            "CONTROL_FLOW": EdgeType.CFG,
            "DFG_ARG_PASS": EdgeType.DFG,
            "DFG_RET": EdgeType.DFG,
            "DFG_VAR_USE": EdgeType.DFG,
            "DFG_CLOSURE": EdgeType.DFG,
            "DFG_CALLBACK": EdgeType.DFG,
            "DFG_TUPLE_UNPACK": EdgeType.DFG,
            "DFG_UNCERTAIN": EdgeType.DFG,
        }
        
        return type_mapping.get(cpg_edge_type, EdgeType.UNKNOWN)
