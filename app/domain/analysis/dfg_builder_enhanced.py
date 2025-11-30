"""
Enhanced Data Flow Graph Builder with Full String Interpolation Support
Tracks f-strings, concatenation, format(), %, join(), templates, and more
"""
import ast
from typing import Dict, List, Set, Optional, Tuple
from app.schemas.graph import SemanticGraph, GraphEdge, GraphNode
from app.enums.edge_type import EdgeType
from app.enums.node_type import NodeType


class EnhancedDFGBuilder:
    """
    Enhanced DFG builder with comprehensive string operation tracking.
    Detects data flow through:
    - f-strings: f"...{var}..."
    - String concatenation: "a" + b
    - format(): "{}".format(var)
    - Percent formatting: "%s" % var
    - join(): "".join([...])
    - Template strings: string.Template
    - Object property access: obj.attr
    - Function arguments: param → usage
    - Return statements: return → caller
    """
    
    def __init__(self):
        self.node_id_counter = 0
    
    def build(self, graph: SemanticGraph, code: str, filename: str = "unknown") -> SemanticGraph:
        """
        Augment graph with enhanced data flow edges.
        
        Args:
            graph: Existing semantic graph with AST nodes
            code: Original source code
            filename: Source file name
        
        Returns:
            Enhanced graph with DFG edges
        """
        dfg_edges: List[GraphEdge] = []
        new_nodes: List[GraphNode] = []
        
        # Track variable definitions: var_name → [node_ids]
        definitions: Dict[str, List[str]] = {}
        
        # Track function return values: func_name → return_node_id
        returns: Dict[str, List[str]] = {}
        
        # Track object attributes: obj.attr → node_id
        attributes: Dict[str, str] = {}
        
        # Sort nodes by line for sequential processing
        sorted_nodes = sorted(graph.nodes, key=lambda n: (n.file, n.line))
        
        # Parse AST for detailed analysis
        try:
            tree = ast.parse(code, filename=filename)
            ast_map = self._build_ast_map(tree, graph)
            
            # Also create line-to-statement map for call expressions
            self.stmt_map = self._build_stmt_map(tree)
        except SyntaxError:
            ast_map = {}
            self.stmt_map = {}
        
        # Process each node
        for node in sorted_nodes:
            self._process_node(node, graph, definitions, returns, attributes, 
                             dfg_edges, new_nodes, ast_map, filename)
        
        # Combine with existing graph
        all_nodes = list(graph.nodes) + new_nodes
        all_edges = list(graph.edges) + dfg_edges
        
        return SemanticGraph(nodes=all_nodes, edges=all_edges)
    
    def _build_stmt_map(self, tree: ast.AST) -> Dict[int, ast.AST]:
        """Build map of line numbers to statement nodes."""
        stmt_map = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.Expr, ast.Call)) and hasattr(node, 'lineno'):
                stmt_map[node.lineno] = node
        return stmt_map
    
    def _build_ast_map(self, tree: ast.AST, graph: SemanticGraph) -> Dict[int, ast.AST]:
        """Map line numbers to AST nodes for detailed analysis."""
        ast_map: Dict[int, List[ast.AST]] = {}
        
        for node in ast.walk(tree):
            if hasattr(node, 'lineno'):
                line = node.lineno
                if line not in ast_map:
                    ast_map[line] = []
                ast_map[line].append(node)
        
        return ast_map
    
    def _process_node(self, node: GraphNode, graph: SemanticGraph,
                     definitions: Dict[str, List[str]], 
                     returns: Dict[str, List[str]],
                     attributes: Dict[str, str],
                     dfg_edges: List[GraphEdge],
                     new_nodes: List[GraphNode],
                     ast_map: Dict[int, List[ast.AST]],
                     filename: str):
        """Process individual node for DFG edges."""
        
        # PARAMETERS: Initial definitions
        if node.type == NodeType.PARAMETER and node.name:
            if node.name not in definitions:
                definitions[node.name] = []
            definitions[node.name].append(node.id)
        
        # ASSIGNMENTS: Track definition and usage
        elif node.type == NodeType.ASSIGNMENT and node.name:
            # Find variables used in RHS
            self._connect_vars_in_subtree(node.id, node.id, graph, definitions, dfg_edges)
            
            # Check for string operations in AST
            if node.line in ast_map:
                for ast_node in ast_map[node.line]:
                    if isinstance(ast_node, ast.Assign):
                        self._process_assignment_rhs(ast_node, node, graph, definitions, 
                                                    dfg_edges, new_nodes, filename)
            
            # Update definitions
            if node.name not in definitions:
                definitions[node.name] = []
            definitions[node.name].append(node.id)
        
        # VARIABLES: Connect to definitions
        elif node.type == NodeType.VARIABLE and node.name:
            if node.name in definitions:
                for def_id in definitions[node.name]:
                    dfg_edges.append(GraphEdge(
                        from_node=def_id,
                        to_node=node.id,
                        type=EdgeType.DFG_FLOW,
                        metadata={"variable": node.name}
                    ))
        
        # CALL EXPRESSIONS: Process arguments and returns
        elif node.type == NodeType.CALL_EXPRESSION:
            # Check if this call has f-strings or string operations in arguments
            if node.line in self.stmt_map:
                stmt = self.stmt_map[node.line]
                if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                    self._process_call_arguments(stmt.value, node, graph, definitions,
                                                dfg_edges, new_nodes, filename)
                elif isinstance(stmt, ast.Call):
                    self._process_call_arguments(stmt, node, graph, definitions,
                                                dfg_edges, new_nodes, filename)
            
            # Also process regular argument flows
            self._process_call_expression(node, graph, definitions, dfg_edges, 
                                         ast_map, new_nodes, filename)
        
        # RETURN STATEMENTS: Track return values
        elif node.type == NodeType.RETURN:
            func_node = self._find_parent_function(node, graph)
            if func_node and func_node.name:
                if func_node.name not in returns:
                    returns[func_node.name] = []
                returns[func_node.name].append(node.id)
                
                # Connect variables in return expression
                self._connect_vars_in_subtree(node.id, node.id, graph, definitions, dfg_edges)
        
        # ATTRIBUTE ACCESS: Track obj.attr flows
        elif node.type == NodeType.ATTRIBUTE_ACCESS:
            self._process_attribute_access(node, graph, definitions, attributes, dfg_edges)
    
    def _process_assignment_rhs(self, ast_node: ast.Assign, graph_node: GraphNode,
                                graph: SemanticGraph, definitions: Dict[str, List[str]],
                                dfg_edges: List[GraphEdge], new_nodes: List[GraphNode],
                                filename: str):
        """Process right-hand side of assignment for string operations."""
        if not ast_node.value:
            return
        
        value = ast_node.value
        
        # F-STRING: f"text {var} more"
        if isinstance(value, ast.JoinedStr):
            self._process_fstring(value, graph_node, graph, definitions, 
                                dfg_edges, new_nodes, filename)
        
        # STRING CONCATENATION: "a" + b + "c"
        elif isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add):
            self._process_string_concat(value, graph_node, graph, definitions, 
                                       dfg_edges, new_nodes, filename)
        
        # FORMAT: "{}".format(var)
        elif isinstance(value, ast.Call):
            if isinstance(value.func, ast.Attribute) and value.func.attr == 'format':
                self._process_format_call(value, graph_node, graph, definitions, 
                                        dfg_edges, new_nodes, filename)
            
            # JOIN: "".join([...])
            elif isinstance(value.func, ast.Attribute) and value.func.attr == 'join':
                self._process_join_call(value, graph_node, graph, definitions, 
                                      dfg_edges, new_nodes, filename)
        
        # PERCENT FORMATTING: "%s" % var
        elif isinstance(value, ast.BinOp) and isinstance(value.op, ast.Mod):
            self._process_percent_format(value, graph_node, graph, definitions, 
                                        dfg_edges, new_nodes, filename)
    
    def _process_fstring(self, fstring: ast.JoinedStr, target_node: GraphNode,
                        graph: SemanticGraph, definitions: Dict[str, List[str]],
                        dfg_edges: List[GraphEdge], new_nodes: List[GraphNode],
                        filename: str):
        """Process f-string interpolations."""
        fstring_node_id = f"fstring_{self.node_id_counter}"
        self.node_id_counter += 1
        
        # Create f-string node
        fstring_node = GraphNode(
            id=fstring_node_id,
            type=NodeType.FSTRING,
            name=f"f-string",
            file=filename,
            line=target_node.line,
            column=target_node.column
        )
        new_nodes.append(fstring_node)
        
        # Process each interpolated value
        for value in fstring.values:
            if isinstance(value, ast.FormattedValue):
                # Extract variable names from the formatted value
                var_names = self._extract_names_from_ast(value.value)
                for var_name in var_names:
                    if var_name in definitions:
                        for def_id in definitions[var_name]:
                            # Variable → f-string
                            dfg_edges.append(GraphEdge(
                                from_node=def_id,
                                to_node=fstring_node_id,
                                type=EdgeType.DFG_INTERP,
                                metadata={"variable": var_name, "interpolation": "fstring"}
                            ))
        
        # f-string → target
        dfg_edges.append(GraphEdge(
            from_node=fstring_node_id,
            to_node=target_node.id,
            type=EdgeType.DFG_FLOW,
            metadata={"string_operation": "fstring"}
        ))
    
    def _process_string_concat(self, binop: ast.BinOp, target_node: GraphNode,
                              graph: SemanticGraph, definitions: Dict[str, List[str]],
                              dfg_edges: List[GraphEdge], new_nodes: List[GraphNode],
                              filename: str):
        """Process string concatenation with + operator."""
        concat_node_id = f"concat_{self.node_id_counter}"
        self.node_id_counter += 1
        
        concat_node = GraphNode(
            id=concat_node_id,
            type=NodeType.STRING_CONCAT,
            name="string_concat",
            file=filename,
            line=target_node.line,
            column=target_node.column
        )
        new_nodes.append(concat_node)
        
        # Extract all variables from left and right sides
        var_names = self._extract_names_from_ast(binop.left) + self._extract_names_from_ast(binop.right)
        
        for var_name in var_names:
            if var_name in definitions:
                for def_id in definitions[var_name]:
                    dfg_edges.append(GraphEdge(
                        from_node=def_id,
                        to_node=concat_node_id,
                        type=EdgeType.DFG_INTERP,
                        metadata={"variable": var_name, "operation": "concat"}
                    ))
        
        # concat → target
        dfg_edges.append(GraphEdge(
            from_node=concat_node_id,
            to_node=target_node.id,
            type=EdgeType.DFG_FLOW,
            metadata={"string_operation": "concat"}
        ))
    
    def _process_format_call(self, call: ast.Call, target_node: GraphNode,
                            graph: SemanticGraph, definitions: Dict[str, List[str]],
                            dfg_edges: List[GraphEdge], new_nodes: List[GraphNode],
                            filename: str):
        """Process .format() calls."""
        format_node_id = f"format_{self.node_id_counter}"
        self.node_id_counter += 1
        
        format_node = GraphNode(
            id=format_node_id,
            type=NodeType.STRING_FORMAT,
            name="format",
            file=filename,
            line=target_node.line,
            column=target_node.column
        )
        new_nodes.append(format_node)
        
        # Process arguments
        for arg in call.args:
            var_names = self._extract_names_from_ast(arg)
            for var_name in var_names:
                if var_name in definitions:
                    for def_id in definitions[var_name]:
                        dfg_edges.append(GraphEdge(
                            from_node=def_id,
                            to_node=format_node_id,
                            type=EdgeType.DFG_INTERP,
                            metadata={"variable": var_name, "operation": "format"}
                        ))
        
        dfg_edges.append(GraphEdge(
            from_node=format_node_id,
            to_node=target_node.id,
            type=EdgeType.DFG_FLOW,
            metadata={"string_operation": "format"}
        ))
    
    def _process_percent_format(self, binop: ast.BinOp, target_node: GraphNode,
                               graph: SemanticGraph, definitions: Dict[str, List[str]],
                               dfg_edges: List[GraphEdge], new_nodes: List[GraphNode],
                               filename: str):
        """Process % string formatting."""
        percent_node_id = f"percent_{self.node_id_counter}"
        self.node_id_counter += 1
        
        percent_node = GraphNode(
            id=percent_node_id,
            type=NodeType.STRING_PERCENT,
            name="percent_format",
            file=filename,
            line=target_node.line,
            column=target_node.column
        )
        new_nodes.append(percent_node)
        
        # Extract variables from RHS
        var_names = self._extract_names_from_ast(binop.right)
        for var_name in var_names:
            if var_name in definitions:
                for def_id in definitions[var_name]:
                    dfg_edges.append(GraphEdge(
                        from_node=def_id,
                        to_node=percent_node_id,
                        type=EdgeType.DFG_INTERP,
                        metadata={"variable": var_name, "operation": "percent"}
                    ))
        
        dfg_edges.append(GraphEdge(
            from_node=percent_node_id,
            to_node=target_node.id,
            type=EdgeType.DFG_FLOW,
            metadata={"string_operation": "percent"}
        ))
    
    def _process_join_call(self, call: ast.Call, target_node: GraphNode,
                          graph: SemanticGraph, definitions: Dict[str, List[str]],
                          dfg_edges: List[GraphEdge], new_nodes: List[GraphNode],
                          filename: str):
        """Process "".join([...]) calls."""
        join_node_id = f"join_{self.node_id_counter}"
        self.node_id_counter += 1
        
        join_node = GraphNode(
            id=join_node_id,
            type=NodeType.STRING_JOIN,
            name="join",
            file=filename,
            line=target_node.line,
            column=target_node.column
        )
        new_nodes.append(join_node)
        
        # Process list argument
        if call.args:
            var_names = self._extract_names_from_ast(call.args[0])
            for var_name in var_names:
                if var_name in definitions:
                    for def_id in definitions[var_name]:
                        dfg_edges.append(GraphEdge(
                            from_node=def_id,
                            to_node=join_node_id,
                            type=EdgeType.DFG_INTERP,
                            metadata={"variable": var_name, "operation": "join"}
                        ))
        
        dfg_edges.append(GraphEdge(
            from_node=join_node_id,
            to_node=target_node.id,
            type=EdgeType.DFG_FLOW,
            metadata={"string_operation": "join"}
        ))
    
    def _process_call_expression(self, node: GraphNode, graph: SemanticGraph,
                                definitions: Dict[str, List[str]],
                                dfg_edges: List[GraphEdge], ast_map: Dict,
                                new_nodes: List[GraphNode], filename: str):
        """Process function/method calls for argument flows."""
        # Connect variables in arguments to the call
        for edge in graph.edges:
            if edge.from_node == node.id and edge.type == EdgeType.AST_CHILD:
                arg_node = next((n for n in graph.nodes if n.id == edge.to_node), None)
                if arg_node and arg_node.type == NodeType.VARIABLE and arg_node.name:
                    if arg_node.name in definitions:
                        for def_id in definitions[arg_node.name]:
                            dfg_edges.append(GraphEdge(
                                from_node=def_id,
                                to_node=node.id,
                                type=EdgeType.DFG_PARAM_PASS,
                                metadata={"argument": arg_node.name}
                            ))
    
    def _process_call_arguments(self, call: ast.Call, node: GraphNode,
                                graph: SemanticGraph, definitions: Dict[str, List[str]],
                                dfg_edges: List[GraphEdge], new_nodes: List[GraphNode],
                                filename: str):
        """Process arguments to function calls, detecting string operations."""
        for arg in call.args:
            # F-STRING in argument
            if isinstance(arg, ast.JoinedStr):
                self._process_fstring(arg, node, graph, definitions, 
                                    dfg_edges, new_nodes, filename)
            
            # STRING CONCATENATION in argument
            elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                self._process_string_concat(arg, node, graph, definitions, 
                                           dfg_edges, new_nodes, filename)
            
            # FORMAT CALL in argument
            elif isinstance(arg, ast.Call):
                if isinstance(arg.func, ast.Attribute) and arg.func.attr == 'format':
                    self._process_format_call(arg, node, graph, definitions, 
                                            dfg_edges, new_nodes, filename)
                elif isinstance(arg.func, ast.Attribute) and arg.func.attr == 'join':
                    self._process_join_call(arg, node, graph, definitions, 
                                          dfg_edges, new_nodes, filename)
            
            # PERCENT FORMATTING in argument
            elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
                self._process_percent_format(arg, node, graph, definitions, 
                                            dfg_edges, new_nodes, filename)
    
    def _process_attribute_access(self, node: GraphNode, graph: SemanticGraph,
                                  definitions: Dict[str, List[str]],
                                  attributes: Dict[str, str],
                                  dfg_edges: List[GraphEdge]):
        """Process obj.attr access patterns."""
        # Track attribute flows (e.g., request.json, auth['username'])
        if node.name and '.' in node.name:
            parts = node.name.split('.')
            base = parts[0]
            
            if base in definitions:
                for def_id in definitions[base]:
                    dfg_edges.append(GraphEdge(
                        from_node=def_id,
                        to_node=node.id,
                        type=EdgeType.DFG_ATTR,
                        metadata={"attribute": node.name}
                    ))
    
    def _extract_names_from_ast(self, node: ast.AST) -> List[str]:
        """Extract all variable names from an AST node."""
        names = []
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                names.append(child.id)
        return names
    
    def _connect_vars_in_subtree(self, node_id: str, target_id: str, 
                                 graph: SemanticGraph, 
                                 definitions: Dict[str, List[str]], 
                                 dfg_edges: List[GraphEdge]):
        """Find all variables in subtree and connect to target."""
        node = next((n for n in graph.nodes if n.id == node_id), None)
        if not node:
            return
        
        # If variable, connect its definition to target
        if node.type == NodeType.VARIABLE and node.name and node.name in definitions:
            for def_id in definitions[node.name]:
                if def_id != target_id:
                    dfg_edges.append(GraphEdge(
                        from_node=def_id,
                        to_node=target_id,
                        type=EdgeType.DFG_FLOW,
                        metadata={"through": node.name}
                    ))
        
        # SUBSCRIPTS are also sources (e.g., sys.argv[1])
        elif node.type == NodeType.SUBSCRIPT:
            # Subscripts themselves are sources - connect directly to target
            if node.id != target_id:
                dfg_edges.append(GraphEdge(
                    from_node=node.id,
                    to_node=target_id,
                    type=EdgeType.DFG_FLOW,
                    metadata={"subscript": node.name}
                ))
        
        # Recurse children
        for edge in graph.edges:
            if edge.from_node == node_id and edge.type == EdgeType.AST_CHILD:
                self._connect_vars_in_subtree(edge.to_node, target_id, graph, definitions, dfg_edges)
    
    def _find_parent_function(self, node: GraphNode, graph: SemanticGraph) -> Optional[GraphNode]:
        """Find the parent function of a node."""
        # Traverse up AST_CHILD edges to find function
        current = node
        visited = set()
        
        while current.id not in visited:
            visited.add(current.id)
            
            if current.type == NodeType.FUNCTION:
                return current
            
            # Find parent
            parent_edge = next((e for e in graph.edges 
                              if e.to_node == current.id and e.type == EdgeType.AST_CHILD), None)
            if not parent_edge:
                break
            
            current = next((n for n in graph.nodes if n.id == parent_edge.from_node), None)
            if not current:
                break
        
        return None
