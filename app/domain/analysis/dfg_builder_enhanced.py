"""
PRODUCTION-READY DFG Builder for OWASP Top 10 Detection
Enhanced with: Object properties, inter-procedural flows, sanitizers, implicit flows, async
"""
import ast
from typing import Dict, List, Set, Optional, Tuple
from app.schemas.graph import SemanticGraph, GraphEdge, GraphNode
from app.enums.edge_type import EdgeType
from app.enums.node_type import NodeType


class EnhancedDFGBuilder:
    """
    Production-grade DFG builder with comprehensive tracking:
    - String operations: f-strings, concatenation, format(), %, join()
    - Object property tracking: req.body.username
    - Inter-procedural flows: function calls → returns
    - Sanitizer detection: stops taint at safe functions
    - Implicit flows: CFG-based control-dependent taint
    - Async/await flows
    - Method chain tracking
    - Array/dict destructuring
    """
    
    # Known sanitization functions (whitelist)
    SANITIZERS = {
        # HTML escaping
        'html.escape', 'html.unescape', 'cgi.escape',
        'markupsafe.escape', 'jinja2.escape',
        # SQL parameterization
        'psycopg2.sql.SQL', 'sqlite3.connect',
        # URL encoding
        'urllib.parse.quote', 'urllib.parse.quote_plus',
        # Command sanitization
        'shlex.quote', 'pipes.quote',
        # Generic validation
        'validate', 'sanitize', 'clean', 'escape', 'filter'
    }
    
    # Dangerous sinks (for implicit flow tracking)
    SINKS = {
        'cursor.execute', 'db.execute', 'os.system', 'subprocess.call',
        'eval', 'exec', '__import__', 'compile',
        'pickle.loads', 'yaml.load', 'json.loads'
    }
    
    def __init__(self):
        self.node_id_counter = 0
    
    def build(self, graph: SemanticGraph, code: str, filename: str = "unknown") -> SemanticGraph:
        """
        Augment graph with production-grade DFG edges.
        
        Args:
            graph: Existing semantic graph with AST nodes
            code: Original source code
            filename: Source file name
        
        Returns:
            Enhanced graph with comprehensive DFG edges
        """
        dfg_edges: List[GraphEdge] = []
        new_nodes: List[GraphNode] = []
        
        # Track variable definitions: var_name → [node_ids]
        definitions: Dict[str, List[str]] = {}
        
        # Track object properties: obj.prop → node_id
        properties: Dict[str, str] = {}
        
        # Track function returns: func_name → [return_node_ids]
        returns: Dict[str, List[str]] = {}
        
        # Track call sites: func_name → [call_node_ids]
        call_sites: Dict[str, List[str]] = {}
        
        # Track sanitized variables: var_name → True
        sanitized: Set[str] = set()
        
        # Parse AST for detailed analysis
        try:
            tree = ast.parse(code, filename=filename)
            ast_map = self._build_ast_map(tree, graph)
            self.stmt_map = self._build_stmt_map(tree)
        except SyntaxError:
            ast_map = {}
            self.stmt_map = {}
        
        # Sort nodes by line for sequential processing
        sorted_nodes = sorted(graph.nodes, key=lambda n: (n.file, n.line))
        
        # PHASE 1: Build definitions and property maps
        for node in sorted_nodes:
            self._phase1_definitions(node, graph, definitions, properties,
                                    returns, call_sites, ast_map, filename)
        
        # PHASE 2: Build DFG edges
        for node in sorted_nodes:
            self._phase2_dataflow(node, graph, definitions, properties, returns,
                                 call_sites, sanitized, dfg_edges, new_nodes,
                                 ast_map, filename)
        
        # PHASE 3: Inter-procedural flows
        self._phase3_interprocedural(graph, returns, call_sites, dfg_edges)
        
        # PHASE 4: Implicit flows (CFG-based)
        self._phase4_implicit_flows(graph, definitions, dfg_edges)
        
        # PHASE 5: Async flows
        self._phase5_async_flows(graph, definitions, dfg_edges)
        
        # Combine with existing graph
        all_nodes = list(graph.nodes) + new_nodes
        all_edges = list(graph.edges) + dfg_edges
        
        return SemanticGraph(nodes=all_nodes, edges=all_edges)
    
    
    # ================================================================
    # PHASE 1: BUILD DEFINITION MAPS
    # ================================================================
    
    def _phase1_definitions(self, node: GraphNode, graph: SemanticGraph,
                           definitions: Dict[str, List[str]],
                           properties: Dict[str, str],
                           returns: Dict[str, List[str]],
                           call_sites: Dict[str, List[str]],
                           ast_map: Dict, filename: str):
        """Build definition and call site maps."""
        
        # Parameters: initial definitions
        if node.type == NodeType.PARAMETER and node.name:
            if node.name not in definitions:
                definitions[node.name] = []
            definitions[node.name].append(node.id)
        
        # Assignments: track definitions
        elif node.type == NodeType.ASSIGNMENT and node.name:
            if node.name not in definitions:
                definitions[node.name] = []
            definitions[node.name].append(node.id)
        
        # Member expressions: track properties
        elif node.type == NodeType.MEMBER_EXPRESSION and node.name:
            properties[node.name] = node.id
        
        # Subscripts: track array/dict access
        elif node.type == NodeType.SUBSCRIPT and node.name:
            properties[node.name] = node.id
        
        # Returns: track function returns
        elif node.type == NodeType.RETURN:
            func = self._find_parent_function(node, graph)
            if func and func.name:
                if func.name not in returns:
                    returns[func.name] = []
                returns[func.name].append(node.id)
        
        # Call expressions: track call sites
        elif node.type == NodeType.CALL_EXPRESSION and node.name:
            if node.name not in call_sites:
                call_sites[node.name] = []
            call_sites[node.name].append(node.id)
    
    # ================================================================
    # PHASE 2: BUILD DATAFLOW EDGES
    # ================================================================
    
    def _phase2_dataflow(self, node: GraphNode, graph: SemanticGraph,
                        definitions: Dict[str, List[str]],
                        properties: Dict[str, str],
                        returns: Dict[str, List[str]],
                        call_sites: Dict[str, List[str]],
                        sanitized: Set[str],
                        dfg_edges: List[GraphEdge],
                        new_nodes: List[GraphNode],
                        ast_map: Dict, filename: str):
        """Build DFG edges for each node type."""
        
        # ASSIGNMENTS: Process RHS
        if node.type == NodeType.ASSIGNMENT and node.name:
            # Check for string operations
            if node.line in ast_map:
                for ast_node in ast_map[node.line]:
                    if isinstance(ast_node, ast.Assign):
                        self._process_assignment_rhs(ast_node, node, graph,
                                                    definitions, properties,
                                                    sanitized, dfg_edges,
                                                    new_nodes, filename)
            
            # Regular variable flows
            self._connect_vars_in_subtree(node.id, node.id, graph, definitions,
                                         properties, sanitized, dfg_edges)
        
        # VARIABLES: Connect to definitions
        elif node.type == NodeType.VARIABLE and node.name:
            if node.name in definitions and node.name not in sanitized:
                for def_id in definitions[node.name]:
                    dfg_edges.append(GraphEdge(
                        from_node=def_id,
                        to_node=node.id,
                        type=EdgeType.DFG_FLOW,
                        metadata={"variable": node.name}
                    ))
        
        # MEMBER EXPRESSIONS: Object property flows
        elif node.type == NodeType.MEMBER_EXPRESSION and node.name:
            self._process_property_access(node, graph, definitions, properties,
                                         sanitized, dfg_edges)
        
        # SUBSCRIPTS: Array/dict access
        elif node.type == NodeType.SUBSCRIPT and node.name:
            self._process_subscript_access(node, graph, definitions, properties,
                                          sanitized, dfg_edges)
        
        # CALL EXPRESSIONS: Check for sanitizers
        elif node.type == NodeType.CALL_EXPRESSION and node.name:
            if self._is_sanitizer(node.name):
                # Mark arguments as sanitized
                for edge in graph.edges:
                    if edge.from_node == node.id and edge.type == EdgeType.AST_CHILD:
                        arg = self._get_node_by_id(edge.to_node, graph)
                        if arg and arg.name:
                            sanitized.add(arg.name)
            
            # Process call arguments (including string ops)
            if node.line in self.stmt_map:
                stmt = self.stmt_map[node.line]
                if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                    self._process_call_arguments(stmt.value, node, graph,
                                                definitions, properties, sanitized,
                                                dfg_edges, new_nodes, filename)
        
        # FSTRINGS: Process interpolated variables
        elif node.type == NodeType.FSTRING:
            # Find all VARIABLE children of this f-string
            for edge in graph.edges:
                if edge.from_node == node.id and edge.type == EdgeType.AST_CHILD:
                    child = self._get_node_by_id(edge.to_node, graph)
                    if child and child.type == NodeType.VARIABLE and child.name:
                        if child.name in sanitized:
                            continue  # Skip sanitized variables
                        
                        # Connect variable definition → f-string
                        if child.name in definitions:
                            for def_id in definitions[child.name]:
                                dfg_edges.append(GraphEdge(
                                    from_node=def_id,
                                    to_node=node.id,
                                    type=EdgeType.DFG_INTERP,
                                    metadata={"variable": child.name, "interpolation": "fstring"}
                                ))
            
            # Also connect f-string → parent (if parent is RETURN, ASSIGNMENT, etc.)
            for edge in graph.edges:
                if edge.to_node == node.id and edge.type == EdgeType.AST_CHILD:
                    parent = self._get_node_by_id(edge.from_node, graph)
                    if parent and parent.type in (NodeType.RETURN, NodeType.ASSIGNMENT, NodeType.CALL_EXPRESSION):
                        dfg_edges.append(GraphEdge(
                            from_node=node.id,
                            to_node=parent.id,
                            type=EdgeType.DFG_FLOW,
                            metadata={"string_operation": "fstring"}
                        ))
        
        # RETURN STATEMENTS: Connect variables in return expressions
        elif node.type == NodeType.RETURN:
            # Connect all variables/expressions in return subtree
            self._connect_vars_in_subtree(node.id, node.id, graph, definitions,
                                         properties, sanitized, dfg_edges)
    
    # ================================================================
    # PHASE 3: INTER-PROCEDURAL FLOWS
    # ================================================================
    
    def _phase3_interprocedural(self, graph: SemanticGraph,
                                returns: Dict[str, List[str]],
                                call_sites: Dict[str, List[str]],
                                dfg_edges: List[GraphEdge]):
        """Connect function returns to call sites."""
        for func_name, return_ids in returns.items():
            if func_name in call_sites:
                for call_id in call_sites[func_name]:
                    for return_id in return_ids:
                        # Return value → call site
                        dfg_edges.append(GraphEdge(
                            from_node=return_id,
                            to_node=call_id,
                            type=EdgeType.DFG_RET,
                            metadata={"function": func_name}
                        ))
    
    # ================================================================
    # PHASE 4: IMPLICIT FLOWS (CFG-based)
    # ================================================================
    
    def _phase4_implicit_flows(self, graph: SemanticGraph,
                               definitions: Dict[str, List[str]],
                               dfg_edges: List[GraphEdge]):
        """
        Track control-dependent taint:
        if secret_condition:
            data = "safe"
        else:
            data = user_input  # Tainted only on FALSE branch
        """
        # Find all CFG_TRUE and CFG_FALSE edges
        for edge in graph.edges:
            if edge.type in (EdgeType.CFG_TRUE, EdgeType.CFG_FALSE):
                # Find assignments in this branch
                branch_node = self._get_node_by_id(edge.to_node, graph)
                if branch_node and branch_node.type == NodeType.ASSIGNMENT:
                    # Mark this assignment as control-dependent
                    dfg_edges.append(GraphEdge(
                        from_node=edge.from_node,
                        to_node=edge.to_node,
                        type=EdgeType.DFG_FLOW,
                        metadata={"branch": edge.type.value, "control_dependent": True}
                    ))
    
    # ================================================================
    # PHASE 5: ASYNC FLOWS
    # ================================================================
    
    def _phase5_async_flows(self, graph: SemanticGraph,
                           definitions: Dict[str, List[str]],
                           dfg_edges: List[GraphEdge]):
        """Track taint through await expressions."""
        for node in graph.nodes:
            if node.type != NodeType.AWAIT_EXPRESSION:
                continue
            
            # Find awaited call
            for edge in graph.edges:
                if edge.from_node == node.id and edge.type == EdgeType.AST_CHILD:
                    awaited = self._get_node_by_id(edge.to_node, graph)
                    if awaited and awaited.type == NodeType.CALL_EXPRESSION:
                        # Await suspends - data flows through suspension
                        dfg_edges.append(GraphEdge(
                            from_node=awaited.id,
                            to_node=node.id,
                            type=EdgeType.DFG_FLOW,
                            metadata={"async_call": awaited.name, "async_flow": True}
                        ))
    
    # ================================================================
    # OBJECT PROPERTY TRACKING
    # ================================================================
    
    def _process_property_access(self, node: GraphNode, graph: SemanticGraph,
                                definitions: Dict[str, List[str]],
                                properties: Dict[str, str],
                                sanitized: Set[str],
                                dfg_edges: List[GraphEdge]):
        """
        Track: req.body.username
        If req is tainted, then req.body is tainted, then req.body.username is tainted
        """
        if not node.name or '.' not in node.name:
            return
        
        parts = node.name.split('.')
        
        # Check each prefix: req, req.body, req.body.username
        for i in range(len(parts)):
            prefix = '.'.join(parts[:i+1])
            
            # Check if prefix is defined and tainted
            if prefix in definitions and prefix not in sanitized:
                for def_id in definitions[prefix]:
                    dfg_edges.append(GraphEdge(
                        from_node=def_id,
                        to_node=node.id,
                        type=EdgeType.DFG_PROPERTY,
                        metadata={"property": node.name, "base": prefix}
                    ))
            
            # Also check if prefix is in properties map
            if prefix in properties and prefix not in sanitized:
                dfg_edges.append(GraphEdge(
                    from_node=properties[prefix],
                    to_node=node.id,
                    type=EdgeType.DFG_PROPERTY,
                    metadata={"property": node.name}
                ))
    
    def _process_subscript_access(self, node: GraphNode, graph: SemanticGraph,
                                 definitions: Dict[str, List[str]],
                                 properties: Dict[str, str],
                                 sanitized: Set[str],
                                 dfg_edges: List[GraphEdge]):
        """
        Track: user['username'], sys.argv[1]
        If user is tainted, then user['username'] is tainted
        """
        if not node.name:
            return
        
        # Extract base: user['username'] → user
        base = node.name.split('[')[0] if '[' in node.name else node.name
        
        if base in definitions and base not in sanitized:
            for def_id in definitions[base]:
                dfg_edges.append(GraphEdge(
                    from_node=def_id,
                    to_node=node.id,
                    type=EdgeType.DFG_FLOW,
                    metadata={"subscript": node.name, "base": base}
                ))
    
    # ================================================================
    # STRING OPERATIONS
    # ================================================================
    
    
    def _process_assignment_rhs(self, ast_node: ast.Assign, graph_node: GraphNode,
                                graph: SemanticGraph, definitions: Dict[str, List[str]],
                                properties: Dict[str, str], sanitized: Set[str],
                                dfg_edges: List[GraphEdge], new_nodes: List[GraphNode],
                                filename: str):
        """Process right-hand side of assignment for string operations."""
        if not ast_node.value:
            return
        
        value = ast_node.value
        
        # F-STRING: f"text {var} more"
        if isinstance(value, ast.JoinedStr):
            self._process_fstring(value, graph_node, graph, definitions, properties,
                                sanitized, dfg_edges, new_nodes, filename)
        
        # STRING CONCATENATION: "a" + b + "c"
        elif isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add):
            self._process_string_concat(value, graph_node, graph, definitions, properties,
                                       sanitized, dfg_edges, new_nodes, filename)
        
        # FORMAT: "{}".format(var)
        elif isinstance(value, ast.Call):
            if isinstance(value.func, ast.Attribute) and value.func.attr == 'format':
                self._process_format_call(value, graph_node, graph, definitions, properties,
                                        sanitized, dfg_edges, new_nodes, filename)
            
            # JOIN: "".join([...])
            elif isinstance(value.func, ast.Attribute) and value.func.attr == 'join':
                self._process_join_call(value, graph_node, graph, definitions, properties,
                                      sanitized, dfg_edges, new_nodes, filename)
        
        # PERCENT FORMATTING: "%s" % var
        elif isinstance(value, ast.BinOp) and isinstance(value.op, ast.Mod):
            self._process_percent_format(value, graph_node, graph, definitions, properties,
                                        sanitized, dfg_edges, new_nodes, filename)
    
    def _process_fstring(self, fstring: ast.JoinedStr, target_node: GraphNode,
                        graph: SemanticGraph, definitions: Dict[str, List[str]],
                        properties: Dict[str, str], sanitized: Set[str],
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
                # Extract variable names AND properties from the formatted value
                var_names = self._extract_names_and_properties(value.value)
                for var_name in var_names:
                    if var_name in sanitized:
                        continue  # Skip sanitized variables
                    
                    if var_name in definitions:
                        for def_id in definitions[var_name]:
                            # Variable → f-string
                            dfg_edges.append(GraphEdge(
                                from_node=def_id,
                                to_node=fstring_node_id,
                                type=EdgeType.DFG_INTERP,
                                metadata={"variable": var_name, "interpolation": "fstring"}
                            ))
                    elif var_name in properties:
                        # Property → f-string
                        dfg_edges.append(GraphEdge(
                            from_node=properties[var_name],
                            to_node=fstring_node_id,
                            type=EdgeType.DFG_INTERP,
                            metadata={"property": var_name, "interpolation": "fstring"}
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
                              properties: Dict[str, str], sanitized: Set[str],
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
        
        # Extract all variables and properties from left and right sides
        var_names = (self._extract_names_and_properties(binop.left) + 
                    self._extract_names_and_properties(binop.right))
        
        for var_name in var_names:
            if var_name in sanitized:
                continue
            
            if var_name in definitions:
                for def_id in definitions[var_name]:
                    dfg_edges.append(GraphEdge(
                        from_node=def_id,
                        to_node=concat_node_id,
                        type=EdgeType.DFG_INTERP,
                        metadata={"variable": var_name, "operation": "concat"}
                    ))
            elif var_name in properties:
                dfg_edges.append(GraphEdge(
                    from_node=properties[var_name],
                    to_node=concat_node_id,
                    type=EdgeType.DFG_INTERP,
                    metadata={"property": var_name, "operation": "concat"}
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
                            properties: Dict[str, str], sanitized: Set[str],
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
            var_names = self._extract_names_and_properties(arg)
            for var_name in var_names:
                if var_name in sanitized:
                    continue
                
                if var_name in definitions:
                    for def_id in definitions[var_name]:
                        dfg_edges.append(GraphEdge(
                            from_node=def_id,
                            to_node=format_node_id,
                            type=EdgeType.DFG_INTERP,
                            metadata={"variable": var_name, "operation": "format"}
                        ))
                elif var_name in properties:
                    dfg_edges.append(GraphEdge(
                        from_node=properties[var_name],
                        to_node=format_node_id,
                        type=EdgeType.DFG_INTERP,
                        metadata={"property": var_name, "operation": "format"}
                    ))
        
        dfg_edges.append(GraphEdge(
            from_node=format_node_id,
            to_node=target_node.id,
            type=EdgeType.DFG_FLOW,
            metadata={"string_operation": "format"}
        ))
    
    def _process_percent_format(self, binop: ast.BinOp, target_node: GraphNode,
                               graph: SemanticGraph, definitions: Dict[str, List[str]],
                               properties: Dict[str, str], sanitized: Set[str],
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
        var_names = self._extract_names_and_properties(binop.right)
        for var_name in var_names:
            if var_name in sanitized:
                continue
            
            if var_name in definitions:
                for def_id in definitions[var_name]:
                    dfg_edges.append(GraphEdge(
                        from_node=def_id,
                        to_node=percent_node_id,
                        type=EdgeType.DFG_INTERP,
                        metadata={"variable": var_name, "operation": "percent"}
                    ))
            elif var_name in properties:
                dfg_edges.append(GraphEdge(
                    from_node=properties[var_name],
                    to_node=percent_node_id,
                    type=EdgeType.DFG_INTERP,
                    metadata={"property": var_name, "operation": "percent"}
                ))
        
        dfg_edges.append(GraphEdge(
            from_node=percent_node_id,
            to_node=target_node.id,
            type=EdgeType.DFG_FLOW,
            metadata={"string_operation": "percent"}
        ))
    
    def _process_join_call(self, call: ast.Call, target_node: GraphNode,
                          graph: SemanticGraph, definitions: Dict[str, List[str]],
                          properties: Dict[str, str], sanitized: Set[str],
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
            var_names = self._extract_names_and_properties(call.args[0])
            for var_name in var_names:
                if var_name in sanitized:
                    continue
                
                if var_name in definitions:
                    for def_id in definitions[var_name]:
                        dfg_edges.append(GraphEdge(
                            from_node=def_id,
                            to_node=join_node_id,
                            type=EdgeType.DFG_INTERP,
                            metadata={"variable": var_name, "operation": "join"}
                        ))
                elif var_name in properties:
                    dfg_edges.append(GraphEdge(
                        from_node=properties[var_name],
                        to_node=join_node_id,
                        type=EdgeType.DFG_INTERP,
                        metadata={"property": var_name, "operation": "join"}
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
                                properties: Dict[str, str], sanitized: Set[str],
                                dfg_edges: List[GraphEdge], new_nodes: List[GraphNode],
                                filename: str):
        """Process arguments to function calls, detecting string operations."""
        for arg in call.args:
            # F-STRING in argument
            if isinstance(arg, ast.JoinedStr):
                self._process_fstring(arg, node, graph, definitions, properties,
                                    sanitized, dfg_edges, new_nodes, filename)
            
            # STRING CONCATENATION in argument
            elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                self._process_string_concat(arg, node, graph, definitions, properties,
                                           sanitized, dfg_edges, new_nodes, filename)
            
            # FORMAT CALL in argument
            elif isinstance(arg, ast.Call):
                if isinstance(arg.func, ast.Attribute) and arg.func.attr == 'format':
                    self._process_format_call(arg, node, graph, definitions, properties,
                                            sanitized, dfg_edges, new_nodes, filename)
                elif isinstance(arg.func, ast.Attribute) and arg.func.attr == 'join':
                    self._process_join_call(arg, node, graph, definitions, properties,
                                          sanitized, dfg_edges, new_nodes, filename)
            
            # PERCENT FORMATTING in argument
            elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod):
                self._process_percent_format(arg, node, graph, definitions, properties,
                                            sanitized, dfg_edges, new_nodes, filename)
    
    # ================================================================
    # HELPER METHODS
    # ================================================================
    
    def _extract_names_and_properties(self, node: ast.AST) -> List[str]:
        """
        Extract all variable names AND property chains from an AST node.
        Returns: ["var", "obj.prop", "obj.prop.nested"]
        """
        names = []
        
        for child in ast.walk(node):
            # Simple variable: x
            if isinstance(child, ast.Name):
                names.append(child.id)
            
            # Property chain: obj.prop.nested
            elif isinstance(child, ast.Attribute):
                chain = self._get_property_chain(child)
                if chain:
                    names.append(chain)
            
            # Subscript: arr[0], dict['key']
            elif isinstance(child, ast.Subscript):
                if isinstance(child.value, ast.Name):
                    names.append(child.value.id)
                elif isinstance(child.value, ast.Attribute):
                    chain = self._get_property_chain(child.value)
                    if chain:
                        names.append(chain)
        
        return list(set(names))  # Deduplicate
    
    def _get_property_chain(self, node: ast.Attribute) -> str:
        """
        Build full property chain from ast.Attribute.
        req.body.username → "req.body.username"
        """
        parts = []
        current = node
        
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        
        if isinstance(current, ast.Name):
            parts.append(current.id)
            parts.reverse()
            return '.'.join(parts)
        
        return ''
    
    def _is_sanitizer(self, func_name: str) -> bool:
        """Check if function is a known sanitizer."""
        if not func_name:
            return False
        
        # Check full name (html.escape) or last part (escape)
        if func_name in self.SANITIZERS:
            return True
        
        # Check last part: markupsafe.escape → escape
        if '.' in func_name:
            last_part = func_name.split('.')[-1]
            # Check if any sanitizer ends with this part
            for sanitizer in self.SANITIZERS:
                if sanitizer.endswith(last_part):
                    return True
        
        return False
    
    def _connect_vars_in_subtree(self, node_id: str, target_id: str, 
                                 graph: SemanticGraph, 
                                 definitions: Dict[str, List[str]],
                                 properties: Dict[str, str],
                                 sanitized: Set[str],
                                 dfg_edges: List[GraphEdge]):
        """Find all variables and properties in subtree and connect to target."""
        node = next((n for n in graph.nodes if n.id == node_id), None)
        if not node:
            return
        
        # If variable, connect its definition to target (unless sanitized)
        if node.type == NodeType.VARIABLE and node.name:
            if node.name in sanitized:
                return  # Skip sanitized variables
            
            if node.name in definitions:
                for def_id in definitions[node.name]:
                    if def_id != target_id:
                        dfg_edges.append(GraphEdge(
                            from_node=def_id,
                            to_node=target_id,
                            type=EdgeType.DFG_FLOW,
                            metadata={"through": node.name}
                        ))
        
        # Member expressions: req.body
        elif node.type == NodeType.MEMBER_EXPRESSION and node.name:
            if node.name in sanitized:
                return
            
            if node.name in properties:
                dfg_edges.append(GraphEdge(
                    from_node=properties[node.name],
                    to_node=target_id,
                    type=EdgeType.DFG_PROPERTY,
                    metadata={"property": node.name}
                ))
        
        # SUBSCRIPTS: sys.argv[1], user['name']
        elif node.type == NodeType.SUBSCRIPT and node.name:
            if node.name in sanitized:
                return
            
            # Extract base: user['name'] → user
            base = node.name.split('[')[0]
            if base in definitions and base not in sanitized:
                for def_id in definitions[base]:
                    if def_id != target_id:
                        dfg_edges.append(GraphEdge(
                            from_node=def_id,
                            to_node=target_id,
                            type=EdgeType.DFG_FLOW,
                            metadata={"subscript": node.name}
                        ))
        
        # Recurse children
        for edge in graph.edges:
            if edge.from_node == node_id and edge.type == EdgeType.AST_CHILD:
                self._connect_vars_in_subtree(edge.to_node, target_id, graph, 
                                             definitions, properties, sanitized, dfg_edges)
    
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
    
    def _get_node_by_id(self, node_id: str, graph: SemanticGraph) -> Optional[GraphNode]:
        """Get a node by its ID."""
        return next((n for n in graph.nodes if n.id == node_id), None)
    
    def _build_stmt_map(self, tree: ast.AST) -> Dict[int, ast.AST]:
        """Build map of line numbers to statement nodes."""
        stmt_map = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.Expr, ast.Call, ast.Assign)) and hasattr(node, 'lineno'):
                stmt_map[node.lineno] = node
        return stmt_map
    
    def _build_ast_map(self, tree: ast.AST, graph: SemanticGraph) -> Dict[int, List[ast.AST]]:
        """Map line numbers to AST nodes for detailed analysis."""
        ast_map: Dict[int, List[ast.AST]] = {}
        
        for node in ast.walk(tree):
            if hasattr(node, 'lineno'):
                line = node.lineno
                if line not in ast_map:
                    ast_map[line] = []
                ast_map[line].append(node)
        
        return ast_map
