from app.schemas.graph import SemanticGraph, GraphEdge, GraphNode
from app.enums.edge_type import EdgeType
from app.enums.node_type import NodeType


class DFGBuilder:
    """
    Data Flow Graph builder.
    Tracks variable definitions and uses, creating DFG_FLOW edges.
    """
    
    def build(self, graph: SemanticGraph) -> SemanticGraph:
        """Augment graph with data flow edges."""
        dfg_edges: list[GraphEdge] = []
        
        # Track variable definitions: var_name -> [node_ids]
        definitions: dict[str, list[str]] = {}
        
        # Sort nodes by file and line
        sorted_nodes = sorted(graph.nodes, key=lambda n: (n.file, n.line))
        
        for node in sorted_nodes:
            # Parameters are initial definitions
            if node.type == NodeType.PARAMETER and node.name:
                if node.name not in definitions:
                    definitions[node.name] = []
                definitions[node.name].append(node.id)
            
            # Assignment: connect variables used in value to assignment, then define new value
            elif node.type == NodeType.ASSIGNMENT and node.name:
                # Find variables used in RHS
                self._connect_vars_in_subtree(node.id, node.id, graph, definitions, dfg_edges)
                
                # Assignment becomes new definition
                if node.name not in definitions:
                    definitions[node.name] = []
                definitions[node.name].append(node.id)
            
            # Variable use
            elif node.type == NodeType.VARIABLE and node.name:
                if node.name in definitions:
                    for def_id in definitions[node.name]:
                        dfg_edges.append(GraphEdge(
                            from_node=def_id,
                            to_node=node.id,
                            type=EdgeType.DFG_FLOW,
                            metadata={"variable": node.name}
                        ))
            
            # Call expression: connect variables in arguments
            elif node.type == NodeType.CALL_EXPRESSION:
                for edge in graph.edges:
                    if edge.from_node == node.id and edge.type == EdgeType.AST_CHILD:
                        arg_node = next((n for n in graph.nodes if n.id == edge.to_node), None)
                        if arg_node and arg_node.type == NodeType.VARIABLE and arg_node.name:
                            if arg_node.name in definitions:
                                for def_id in definitions[arg_node.name]:
                                    dfg_edges.append(GraphEdge(
                                        from_node=def_id,
                                        to_node=node.id,
                                        type=EdgeType.DFG_FLOW,
                                        metadata={"via_argument": arg_node.name}
                                    ))
        
        all_edges = list(graph.edges) + dfg_edges
        return SemanticGraph(nodes=graph.nodes, edges=all_edges)
    
    def _connect_vars_in_subtree(self, node_id: str, target_id: str, graph: SemanticGraph, 
                                   definitions: dict, dfg_edges: list):
        """Find all variables in subtree and connect to target."""
        node = next((n for n in graph.nodes if n.id == node_id), None)
        if not node:
            return
        
        # If variable, connect its definition to target
        if node.type == NodeType.VARIABLE and node.name and node.name in definitions:
            for def_id in definitions[node.name]:
                # Avoid self-loops
                if def_id != target_id:
                    dfg_edges.append(GraphEdge(
                        from_node=def_id,
                        to_node=target_id,
                        type=EdgeType.DFG_FLOW,
                        metadata={"through": node.name}
                    ))
        
        # Recurse children
        for edge in graph.edges:
            if edge.from_node == node_id and edge.type == EdgeType.AST_CHILD:
                self._connect_vars_in_subtree(edge.to_node, target_id, graph, definitions, dfg_edges)
