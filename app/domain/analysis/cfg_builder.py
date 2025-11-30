from app.schemas.graph import SemanticGraph, GraphEdge
from app.enums.edge_type import EdgeType
from app.enums.node_type import NodeType


class CFGBuilder:
    """
    Control Flow Graph builder.
    Connects nodes via CFG_NEXT edges based on execution order.
    """
    
    def build(self, graph: SemanticGraph) -> SemanticGraph:
        """Augment graph with control flow edges."""
        cfg_edges: list[GraphEdge] = []
        
        # Group nodes by file and line number for sequential ordering
        statement_nodes = [
            n for n in graph.nodes 
            if n.type in (
                NodeType.ASSIGNMENT,
                NodeType.RETURN,
                NodeType.CALL_EXPRESSION,
                NodeType.IF_STATEMENT,
                NodeType.FOR_STATEMENT,
                NodeType.WHILE_STATEMENT,
                NodeType.TRY_STATEMENT
            )
        ]
        
        # Sort by file, then line
        statement_nodes.sort(key=lambda n: (n.file, n.line))
        
        # Connect sequential statements within same file
        current_file = None
        prev_node = None
        
        for node in statement_nodes:
            if current_file != node.file:
                current_file = node.file
                prev_node = None
            
            if prev_node:
                cfg_edges.append(GraphEdge(
                    from_node=prev_node.id,
                    to_node=node.id,
                    type=EdgeType.CFG_NEXT
                ))
            
            prev_node = node
        
        # Merge with existing edges
        all_edges = list(graph.edges) + cfg_edges
        return SemanticGraph(nodes=graph.nodes, edges=all_edges)
