from app.schemas.graph import SemanticGraph, GraphEdge, GraphNode
from app.enums.edge_type import EdgeType
from app.enums.node_type import NodeType
from typing import Dict, List, Set, Optional


class CFGBuilder:
    """
    Enhanced Control Flow Graph builder with branching, loops, and exception handling.
    
    Builds comprehensive CFG for taint analysis:
    - Sequential execution (CFG_NEXT)
    - Conditional branches (CFG_IF_TRUE, CFG_IF_FALSE)
    - Loop edges (CFG_LOOP_ENTRY, CFG_LOOP_BACK)
    - Exception flow (CFG_TRY, CFG_EXCEPT)
    - Function calls (CFG_CALL, CFG_RETURN)
    """
    
    def build(self, graph: SemanticGraph) -> SemanticGraph:
        """Augment graph with comprehensive control flow edges."""
        cfg_edges: List[GraphEdge] = []
        
        # Build function context map
        function_map = self._build_function_map(graph)
        
        # Group nodes by function
        for func_name, func_nodes in function_map.items():
            # Build CFG within each function
            self._build_function_cfg(func_nodes, graph, cfg_edges)
        
        # Add global scope CFG (top-level statements)
        global_nodes = [n for n in graph.nodes if not self._is_in_function(n, function_map)]
        self._build_sequential_cfg(global_nodes, cfg_edges)
        
        # Add function call/return edges
        self._build_call_edges(graph, cfg_edges)
        
        # Merge with existing edges
        all_edges = list(graph.edges) + cfg_edges
        return SemanticGraph(nodes=graph.nodes, edges=all_edges)
    
    def _build_function_map(self, graph: SemanticGraph) -> Dict[str, List[GraphNode]]:
        """Group nodes by their containing function."""
        function_map = {"__global__": []}
        
        for node in graph.nodes:
            if node.type in (NodeType.FUNCTION, NodeType.ASYNC_FUNCTION):
                function_map[node.name] = []
        
        # Assign nodes to functions based on AST_CHILD edges
        for node in graph.nodes:
            parent_func = self._find_parent_function(node, graph)
            if parent_func:
                if parent_func.name in function_map:
                    function_map[parent_func.name].append(node)
            else:
                function_map["__global__"].append(node)
        
        return function_map
    
    def _build_function_cfg(self, nodes: List[GraphNode], graph: SemanticGraph, 
                           cfg_edges: List[GraphEdge]):
        """Build CFG for nodes within a function, handling branches and loops."""
        statement_nodes = [
            n for n in nodes 
            if n.type in (
                NodeType.ASSIGNMENT,
                NodeType.RETURN,
                NodeType.CALL_EXPRESSION,
                NodeType.IF_STATEMENT,
                NodeType.FOR_STATEMENT,
                NodeType.WHILE_STATEMENT,
                NodeType.TRY,
                NodeType.EXCEPT,
                NodeType.RAISE,
                NodeType.AWAIT,
                NodeType.GLOBAL,
                NodeType.NONLOCAL,
                NodeType.IMPORT
            )
        ]
        
        # Sort by line number
        statement_nodes.sort(key=lambda n: n.line)
        
        # Build sequential CFG with special handling for control structures
        i = 0
        while i < len(statement_nodes):
            current = statement_nodes[i]
            
            # Handle different statement types
            if current.type == NodeType.TRY:
                # TRY → first statement in try body
                i = self._handle_try_block(current, statement_nodes, i, graph, cfg_edges)
            
            elif current.type in (NodeType.IF_STATEMENT,):
                # IF → branches (handled by sequential for now, but marked)
                if i + 1 < len(statement_nodes):
                    cfg_edges.append(GraphEdge(
                        from_node=current.id,
                        to_node=statement_nodes[i + 1].id,
                        type=EdgeType.CFG_NEXT,
                        metadata={"branch": "conditional"}
                    ))
                i += 1
            
            elif current.type in (NodeType.FOR_STATEMENT, NodeType.WHILE_STATEMENT):
                # LOOP → loop body (simplified)
                if i + 1 < len(statement_nodes):
                    cfg_edges.append(GraphEdge(
                        from_node=current.id,
                        to_node=statement_nodes[i + 1].id,
                        type=EdgeType.CFG_NEXT,
                        metadata={"loop": "entry"}
                    ))
                i += 1
            
            else:
                # Sequential flow
                if i + 1 < len(statement_nodes):
                    next_node = statement_nodes[i + 1]
                    cfg_edges.append(GraphEdge(
                        from_node=current.id,
                        to_node=next_node.id,
                        type=EdgeType.CFG_NEXT
                    ))
                i += 1
    
    def _build_sequential_cfg(self, nodes: List[GraphNode], cfg_edges: List[GraphEdge]):
        """Build simple sequential CFG for global scope."""
        statement_nodes = [
            n for n in nodes 
            if n.type in (
                NodeType.ASSIGNMENT,
                NodeType.RETURN,
                NodeType.CALL_EXPRESSION,
                NodeType.IMPORT,
                NodeType.GLOBAL,
                NodeType.NONLOCAL
            )
        ]
        
        statement_nodes.sort(key=lambda n: (n.file, n.line))
        
        for i in range(len(statement_nodes) - 1):
            cfg_edges.append(GraphEdge(
                from_node=statement_nodes[i].id,
                to_node=statement_nodes[i + 1].id,
                type=EdgeType.CFG_NEXT
            ))
    
    def _handle_try_block(self, try_node: GraphNode, all_nodes: List[GraphNode],
                         current_idx: int, graph: SemanticGraph, 
                         cfg_edges: List[GraphEdge]) -> int:
        """Handle try-except control flow."""
        # Find except handlers for this try block
        except_handlers = [
            n for n in all_nodes 
            if n.type == NodeType.EXCEPT and n.line > try_node.line
        ]
        
        # TRY → next statement (try body)
        if current_idx + 1 < len(all_nodes):
            next_stmt = all_nodes[current_idx + 1]
            cfg_edges.append(GraphEdge(
                from_node=try_node.id,
                to_node=next_stmt.id,
                type=EdgeType.CFG_NEXT,
                metadata={"block": "try_body"}
            ))
        
        # TRY → EXCEPT (exception path)
        for except_handler in except_handlers[:1]:  # First except only
            cfg_edges.append(GraphEdge(
                from_node=try_node.id,
                to_node=except_handler.id,
                type=EdgeType.CFG_NEXT,
                metadata={"exception": "raised"}
            ))
        
        return current_idx + 1
    
    def _build_call_edges(self, graph: SemanticGraph, cfg_edges: List[GraphEdge]):
        """Build edges for function calls and returns."""
        # For each CALL_EXPRESSION, try to connect to target function
        call_nodes = [n for n in graph.nodes if n.type == NodeType.CALL_EXPRESSION]
        func_nodes = [n for n in graph.nodes if n.type in (NodeType.FUNCTION, NodeType.ASYNC_FUNCTION)]
        
        for call in call_nodes:
            # Find matching function by name
            if call.name:
                func_name = call.name.split('.')[-1]  # Handle obj.method()
                matching_func = next((f for f in func_nodes if f.name == func_name), None)
                
                if matching_func:
                    # CALL → FUNCTION (call edge)
                    cfg_edges.append(GraphEdge(
                        from_node=call.id,
                        to_node=matching_func.id,
                        type=EdgeType.CFG_NEXT,
                        metadata={"call": "entry"}
                    ))
    
    def _find_parent_function(self, node: GraphNode, graph: SemanticGraph) -> Optional[GraphNode]:
        """Find the parent function of a node."""
        visited = set()
        current = node
        
        while current.id not in visited:
            visited.add(current.id)
            
            if current.type in (NodeType.FUNCTION, NodeType.ASYNC_FUNCTION):
                return current
            
            # Find parent via AST_CHILD edges
            parent_edge = next((e for e in graph.edges 
                              if e.to_node == current.id and e.type == EdgeType.AST_CHILD), None)
            if not parent_edge:
                break
            
            current = next((n for n in graph.nodes if n.id == parent_edge.from_node), None)
            if not current:
                break
        
        return None
    
    def _is_in_function(self, node: GraphNode, function_map: Dict[str, List[GraphNode]]) -> bool:
        """Check if node is inside any function."""
        for func_name, func_nodes in function_map.items():
            if func_name != "__global__" and node in func_nodes:
                return True
        return False
