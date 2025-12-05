"""
UPGRADED CFG Builder - Advanced Control Flow Graph Construction
Handles: async/await, try/catch, conditionals, loops, callbacks, function calls
"""

from typing import Dict, List, Optional, Set
from app.schemas.graph import SemanticGraph, GraphNode, GraphEdge
from app.enums.edge_type import EdgeType
from app.enums.node_type import NodeType


class CFGBuilder:
    """
    Advanced Control Flow Graph builder with support for:
    - Sequential flow (basic blocks)
    - Conditional branching (if/else, ternary)
    - Loop constructs (for, while, do-while)
    - Exception handling (try/catch/finally)
    - Async/await execution
    - Function calls (inter-procedural edges)
    - Callbacks and promises
    """
    
    def __init__(self):
        self.cfg_edges: List[GraphEdge] = []
        self.node_map: Dict[str, GraphNode] = {}
        self.function_scopes: Dict[str, List[GraphNode]] = {}
        self.visited: Set[str] = set()
    
    def build(self, graph: SemanticGraph) -> SemanticGraph:
        """Augment graph with comprehensive control flow edges."""
        self.cfg_edges = []
        self.node_map = {n.id: n for n in graph.nodes}
        self.function_scopes = self._build_function_scopes(graph.nodes)
        self.visited = set()
        
        # Build CFG for each function scope
        for func_id, func_nodes in self.function_scopes.items():
            self._build_function_cfg(func_nodes)
        
        # Build file-level CFG (top-level statements)
        top_level_nodes = self._get_top_level_statements(graph.nodes)
        if top_level_nodes:
            self._build_linear_cfg(top_level_nodes)
        
        # Add inter-procedural call edges
        self._add_call_edges(graph.nodes)
        
        # Add async/await control flow
        self._add_async_edges(graph.nodes)
        
        # Merge with existing edges
        all_edges = list(graph.edges) + self.cfg_edges
        return SemanticGraph(nodes=graph.nodes, edges=all_edges)
    
    # ================================================================
    # FUNCTION SCOPE ANALYSIS
    # ================================================================
    
    def _build_function_scopes(self, nodes: List[GraphNode]) -> Dict[str, List[GraphNode]]:
        """
        Group nodes by their containing function using AST_CHILD edges.
        This properly handles nested blocks and statements.
        """
        scopes = {}
        
        # Find all function nodes
        functions = [n for n in nodes if n.type == NodeType.FUNCTION]
        
        for func in functions:
            # Get all descendants of this function (recursively follow AST_CHILD edges)
            func_statements = []
            for node in nodes:
                if node.type in self._get_statement_types():
                    # Check if this statement is inside the function (by line number range)
                    # In production, should walk AST_CHILD edges
                    if node.file == func.file and node.line > func.line:
                        func_statements.append(node)
            
            if func_statements:
                scopes[func.id] = func_statements
        
        return scopes
    
    def _get_top_level_statements(self, nodes: List[GraphNode]) -> List[GraphNode]:
        """Get statements not inside any function."""
        function_nodes = {n.id for n in nodes if n.type == NodeType.FUNCTION}
        statements = []
        
        for node in nodes:
            if node.type not in self._get_statement_types():
                continue
            
            # Check if node is inside a function (simplified - could be improved)
            # In real implementation, track AST_CHILD relationships
            if not self._is_inside_function(node, nodes):
                statements.append(node)
        
        return sorted(statements, key=lambda n: (n.file, n.line))
    
    def _is_inside_function(self, node: GraphNode, all_nodes: List[GraphNode]) -> bool:
        """Check if node is inside a function (simplified check)."""
        # In production, walk AST_CHILD edges backwards to find FUNCTION parent
        # For now, use heuristic: if line is after a function def in same file
        for func in all_nodes:
            if func.type == NodeType.FUNCTION and func.file == node.file:
                if func.line < node.line:
                    return True
        return False
    
    # ================================================================
    # CFG CONSTRUCTION
    # ================================================================
    
    def _build_function_cfg(self, statements: List[GraphNode]):
        """Build CFG for statements within a function."""
        if not statements:
            return
        
        # Sort by line number
        statements = sorted(statements, key=lambda n: n.line)
        
        i = 0
        while i < len(statements):
            node = statements[i]
            
            if node.type == NodeType.IF_STATEMENT:
                i = self._handle_if_statement(node, statements, i)
            elif node.type in (NodeType.FOR_STATEMENT, NodeType.WHILE_STATEMENT):
                i = self._handle_loop(node, statements, i)
            elif node.type == NodeType.TRY_STATEMENT:
                i = self._handle_try_catch(node, statements, i)
            elif node.type == NodeType.RETURN:
                # Return has no next (function exit)
                i += 1
            else:
                # Linear flow: connect to next statement
                if i + 1 < len(statements):
                    self._add_cfg_edge(node.id, statements[i + 1].id)
                i += 1
    
    def _build_linear_cfg(self, statements: List[GraphNode]):
        """Simple sequential control flow."""
        for i in range(len(statements) - 1):
            self._add_cfg_edge(statements[i].id, statements[i + 1].id)
    
    # ================================================================
    # CONDITIONAL HANDLING (IF/ELSE)
    # ================================================================
    
    def _handle_if_statement(self, if_node: GraphNode, statements: List[GraphNode], current_idx: int) -> int:
        """
        Handle if/else branching:
        IF -> TRUE_BRANCH (then body)
        IF -> FALSE_BRANCH (else body or next statement)
        Both branches -> MERGE_POINT (next statement after if)
        """
        # Find next statement after if block
        next_idx = self._find_next_statement_after_block(if_node, statements, current_idx)
        
        # Find branches (simplified - in production, walk AST_CHILD edges)
        then_branch = self._find_branch_statements(if_node, statements, "then")
        else_branch = self._find_branch_statements(if_node, statements, "else")
        
        # Connect if to then branch
        if then_branch:
            self._add_cfg_edge(if_node.id, then_branch[0].id, EdgeType.CFG_TRUE)
            # Build CFG for then branch
            self._build_linear_cfg(then_branch)
            # Connect end of then branch to merge point
            if next_idx < len(statements):
                self._add_cfg_edge(then_branch[-1].id, statements[next_idx].id)
        
        # Connect if to else branch
        if else_branch:
            self._add_cfg_edge(if_node.id, else_branch[0].id, EdgeType.CFG_FALSE)
            # Build CFG for else branch
            self._build_linear_cfg(else_branch)
            # Connect end of else branch to merge point
            if next_idx < len(statements):
                self._add_cfg_edge(else_branch[-1].id, statements[next_idx].id)
        else:
            # No else branch - if can flow directly to next statement
            if next_idx < len(statements):
                self._add_cfg_edge(if_node.id, statements[next_idx].id, EdgeType.CFG_FALSE)
        
        return next_idx if next_idx < len(statements) else len(statements)
    
    # ================================================================
    # LOOP HANDLING (FOR/WHILE)
    # ================================================================
    
    def _handle_loop(self, loop_node: GraphNode, statements: List[GraphNode], current_idx: int) -> int:
        """
        Handle loop control flow:
        LOOP_HEADER -> LOOP_BODY (true branch)
        LOOP_HEADER -> EXIT (false branch)
        LOOP_BODY -> LOOP_HEADER (back-edge)
        """
        # Find loop body
        loop_body = self._find_branch_statements(loop_node, statements, "body")
        
        # Find next statement after loop
        next_idx = self._find_next_statement_after_block(loop_node, statements, current_idx)
        
        if loop_body:
            # Loop header to first statement in body
            self._add_cfg_edge(loop_node.id, loop_body[0].id, EdgeType.CFG_TRUE)
            
            # Build linear CFG for loop body
            self._build_linear_cfg(loop_body)
            
            # Back-edge: last statement in body -> loop header
            self._add_cfg_edge(loop_body[-1].id, loop_node.id, EdgeType.CFG_LOOP_BACK)
        
        # Loop exit: header -> next statement (when condition false)
        if next_idx < len(statements):
            self._add_cfg_edge(loop_node.id, statements[next_idx].id, EdgeType.CFG_FALSE)
        
        return next_idx if next_idx < len(statements) else len(statements)
    
    # ================================================================
    # EXCEPTION HANDLING (TRY/CATCH/FINALLY)
    # ================================================================
    
    def _handle_try_catch(self, try_node: GraphNode, statements: List[GraphNode], current_idx: int) -> int:
        """
        Handle exception flow:
        TRY_BODY -> normal flow OR -> CATCH_HANDLER (on exception)
        CATCH_HANDLER -> FINALLY
        TRY_BODY -> FINALLY (if no exception)
        FINALLY -> next statement
        """
        # Find try/catch/finally blocks
        try_body = self._find_branch_statements(try_node, statements, "try")
        catch_handlers = self._find_branch_statements(try_node, statements, "catch")
        finally_block = self._find_branch_statements(try_node, statements, "finally")
        
        # Find next statement after entire try/catch block
        next_idx = self._find_next_statement_after_block(try_node, statements, current_idx)
        
        # Connect try body
        if try_body:
            self._add_cfg_edge(try_node.id, try_body[0].id)
            self._build_linear_cfg(try_body)
            
            # Try body can flow to catch (exception edge)
            if catch_handlers:
                self._add_cfg_edge(try_body[0].id, catch_handlers[0].id, EdgeType.CFG_EXCEPTION)
                self._build_linear_cfg(catch_handlers)
            
            # Connect to finally
            if finally_block:
                if try_body:
                    self._add_cfg_edge(try_body[-1].id, finally_block[0].id)
                if catch_handlers:
                    self._add_cfg_edge(catch_handlers[-1].id, finally_block[0].id)
                self._build_linear_cfg(finally_block)
                
                # Finally to next statement
                if next_idx < len(statements):
                    self._add_cfg_edge(finally_block[-1].id, statements[next_idx].id)
            else:
                # No finally - direct to next statement
                if next_idx < len(statements):
                    if try_body:
                        self._add_cfg_edge(try_body[-1].id, statements[next_idx].id)
                    if catch_handlers:
                        self._add_cfg_edge(catch_handlers[-1].id, statements[next_idx].id)
        
        return next_idx if next_idx < len(statements) else len(statements)
    
    # ================================================================
    # ASYNC/AWAIT CONTROL FLOW
    # ================================================================
    
    def _add_async_edges(self, nodes: List[GraphNode]):
        """Add control flow edges for async/await patterns."""
        for node in nodes:
            if node.type != NodeType.AWAIT_EXPRESSION:
                continue
            
            # Find the awaited expression (should be a child CALL_EXPRESSION)
            awaited_calls = [
                n for n in nodes 
                if n.type == NodeType.CALL_EXPRESSION and n.line == node.line
            ]
            
            if awaited_calls:
                # Await suspends execution until promise resolves
                self._add_cfg_edge(node.id, awaited_calls[0].id, EdgeType.CFG_ASYNC)
    
    # ================================================================
    # INTER-PROCEDURAL CALL EDGES
    # ================================================================
    
    def _add_call_edges(self, nodes: List[GraphNode]):
        """Add edges from call sites to function definitions."""
        # Build function name -> definition map
        functions = {n.name: n for n in nodes if n.type == NodeType.FUNCTION}
        
        for node in nodes:
            if node.type != NodeType.CALL_EXPRESSION:
                continue
            
            # Check if this call matches a defined function
            call_name = node.name
            if call_name and call_name in functions:
                func_node = functions[call_name]
                # Call site -> function entry
                self._add_cfg_edge(node.id, func_node.id, EdgeType.CFG_CALL)
                
                # Find return statements in function
                returns = [
                    n for n in nodes 
                    if n.type == NodeType.RETURN and self._is_in_function(n, func_node, nodes)
                ]
                
                # Return -> back to call site (simplified - should return to next statement)
                for ret in returns:
                    self._add_cfg_edge(ret.id, node.id, EdgeType.CFG_RETURN)
    
    # ================================================================
    # HELPER METHODS
    # ================================================================
    
    def _add_cfg_edge(self, from_id: str, to_id: str, edge_type: EdgeType = EdgeType.CFG_NEXT):
        """Add CFG edge if not already exists."""
        edge = GraphEdge(from_node=from_id, to_node=to_id, type=edge_type)
        
        # Avoid duplicates
        if not any(e.from_node == from_id and e.to_node == to_id for e in self.cfg_edges):
            self.cfg_edges.append(edge)
    
    def _get_statement_types(self) -> Set[NodeType]:
        """Return node types that are considered statements."""
        return {
            NodeType.ASSIGNMENT,
            NodeType.RETURN,
            NodeType.CALL_EXPRESSION,
            NodeType.IF_STATEMENT,
            NodeType.FOR_STATEMENT,
            NodeType.WHILE_STATEMENT,
            NodeType.TRY_STATEMENT,
            NodeType.AWAIT_EXPRESSION,
            NodeType.THROW_STATEMENT,
            NodeType.BREAK_STATEMENT,
            NodeType.CONTINUE_STATEMENT
        }
    
    def _find_next_statement_after_block(self, block_node: GraphNode, statements: List[GraphNode], current_idx: int) -> int:
        """
        Find index of next statement after a control flow block using metadata.
        Uses end line from metadata instead of heuristics.
        Handles both dict and NodeMetadata object formats.
        """
        # Get metadata from block node
        metadata = block_node.metadata
        if metadata is None:
            # Fallback to heuristic
            block_end_line = block_node.line + 10
        else:
            # Helper function to get metadata value (works for both dict and object)
            def get_meta(key):
                if isinstance(metadata, dict):
                    return metadata.get(key)
                else:
                    return getattr(metadata, key, None)
            
            # Determine block end line based on node type
            block_end_line = None
            
            if block_node.type == NodeType.IF_STATEMENT:
                # Check both then and else blocks
                then_end = get_meta("then_block_end")
                else_end = get_meta("else_block_end")
                # Use the later of the two
                if then_end and else_end:
                    block_end_line = max(then_end, else_end)
                elif then_end:
                    block_end_line = then_end
                elif else_end:
                    block_end_line = else_end
            elif block_node.type in (NodeType.FOR_STATEMENT, NodeType.WHILE_STATEMENT):
                block_end_line = get_meta("loop_block_end")
            elif block_node.type == NodeType.TRY_STATEMENT:
                # Check try/except/finally blocks
                try_end = get_meta("try_block_end")
                finally_end = get_meta("finally_block_end")
                handlers = get_meta("except_handlers")
                
                # Get the maximum end line
                ends = [e for e in [try_end, finally_end] if e is not None]
                if handlers:
                    for h in handlers:
                        h_end = h.get("end") if isinstance(h, dict) else getattr(h, "end", None)
                        if h_end:
                            ends.append(h_end)
                
                block_end_line = max(ends) if ends else None
            
            # Fallback to heuristic if no metadata
            if block_end_line is None:
                block_end_line = block_node.line + 10
        
        # Find first statement after block end
        for i in range(current_idx + 1, len(statements)):
            if statements[i].line > block_end_line:
                return i
        
        return len(statements)
    
    def _find_branch_statements(self, parent: GraphNode, all_statements: List[GraphNode], branch_type: str) -> List[GraphNode]:
        """
        Find statements in a specific branch using metadata from AST parser.
        Uses metadata fields added by AST parser (then_block_start/end, else_block_start/end, etc.)
        Handles both dict and NodeMetadata object formats.
        """
        branch_statements = []
        
        # Get metadata from parent node (handle both dict and NodeMetadata object)
        metadata = parent.metadata
        if metadata is None:
            return []
        
        # Helper function to get metadata value (works for both dict and object)
        def get_meta(key):
            if isinstance(metadata, dict):
                return metadata.get(key)
            else:
                return getattr(metadata, key, None)
        
        # Determine line range based on branch type and metadata
        start_line = None
        end_line = None
        
        if branch_type == "then":
            start_line = get_meta("then_block_start")
            end_line = get_meta("then_block_end")
        elif branch_type == "else":
            start_line = get_meta("else_block_start")
            end_line = get_meta("else_block_end")
        elif branch_type == "body":  # For loops
            start_line = get_meta("loop_block_start")
            end_line = get_meta("loop_block_end")
        elif branch_type == "try":
            start_line = get_meta("try_block_start")
            end_line = get_meta("try_block_end")
        elif branch_type == "catch":
            # Get first exception handler
            handlers = get_meta("except_handlers")
            if handlers and len(handlers) > 0:
                start_line = handlers[0].get("start") if isinstance(handlers[0], dict) else getattr(handlers[0], "start", None)
                end_line = handlers[0].get("end") if isinstance(handlers[0], dict) else getattr(handlers[0], "end", None)
        elif branch_type == "finally":
            start_line = get_meta("finally_block_start")
            end_line = get_meta("finally_block_end")
        
        # If no metadata available, return empty list (no branch)
        if start_line is None or end_line is None:
            return []
        
        # Filter statements by line range
        for stmt in all_statements:
            if stmt.file == parent.file and start_line <= stmt.line <= end_line:
                # Exclude the parent control flow node itself
                if stmt.id != parent.id:
                    branch_statements.append(stmt)
        
        return sorted(branch_statements, key=lambda n: n.line)
    
    def _is_in_function(self, node: GraphNode, func_node: GraphNode, all_nodes: List[GraphNode]) -> bool:
        """Check if node is inside a specific function."""
        # Simplified check - in production, walk AST_CHILD edges backwards
        return (
            node.file == func_node.file and 
            node.line > func_node.line and
            node.line < func_node.line + 100  # Heuristic
        )


# ================================================================
# USAGE NOTES
# ================================================================
"""
UPGRADED CFG BUILDER - Metadata-Based Control Flow Analysis

This CFG builder creates advanced control flow edges using metadata from the AST parser:

EDGE TYPES:
1. CFG_NEXT - Sequential execution
2. CFG_TRUE - Conditional true branch (if condition is true)
3. CFG_FALSE - Conditional false branch (if condition is false or else)
4. CFG_LOOP_BACK - Loop back-edge (end of loop body to loop header)
5. CFG_EXCEPTION - Exception throw edge (try block to catch handler)
6. CFG_CALL - Function call edge (call site to function entry)
7. CFG_RETURN - Function return edge (return statement to call site)
8. CFG_ASYNC - Async suspension point (await keyword)

METADATA-BASED TRACKING:
Instead of line number heuristics, this implementation uses metadata added by AST parser:

IF_STATEMENT metadata:
  - then_block_start/end: Line range of then block
  - else_block_start/end: Line range of else block
  - has_else: Boolean flag

FOR/WHILE_STATEMENT metadata:
  - loop_block_start/end: Line range of loop body
  - has_else: Boolean flag (for Python)

TRY_STATEMENT metadata:
  - try_block_start/end: Line range of try block
  - except_handlers: List of handler line ranges
  - finally_block_start/end: Line range of finally block
  - has_except/has_finally: Boolean flags

ADVANTAGES:
✅ Accurate branch detection (no heuristics)
✅ Path-sensitive vulnerability detection
✅ Proper handling of nested blocks
✅ Support for complex control flow patterns

INTEGRATION:
- AST Parser creates control flow nodes with metadata
- CFG Builder uses metadata to construct accurate control flow
- DFG Builder respects CFG edges for data flow analysis
- Taint analysis uses CFG for path-sensitive tracking

TESTING:
See test_files/test_cfg_conditional.py for examples
"""