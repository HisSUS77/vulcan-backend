"""
Enhanced Data Flow Graph Builder with Taint Tracking
PRIMARY FOCUS: Input-related vulnerabilities (SQL Injection, XSS, Command Injection)

Tracks:
- INPUT SOURCES: request.GET, request.POST, request.args, request.form, request.json, 
                 sys.argv, input(), file uploads, cookies, headers
- TAINT PROPAGATION: Variable assignments, function arguments, string operations
- DANGEROUS SINKS: execute(), eval(), os.system(), innerHTML, etc.
- SANITIZERS: escape(), quote(), parameterize(), etc.
"""
import ast
from typing import Dict, List, Set, Optional, Tuple
from app.schemas.graph import SemanticGraph, GraphEdge, GraphNode
from app.enums.edge_type import EdgeType
from app.enums.node_type import NodeType


class EnhancedDFGBuilder:
    """
    Enhanced DFG builder with INPUT-FOCUSED taint tracking.
    
    Key Features:
    1. INPUT SOURCE IDENTIFICATION - Marks all user input entry points
    2. TAINT PROPAGATION - Tracks taint flow through variables, functions, operations
    3. STRING INTERPOLATION - Tracks f-strings, concat, format, %, join, templates
    4. SANITIZER DETECTION - Identifies validation/sanitization points
    5. PATH EXTRACTION - Complete input → sink paths for vulnerability analysis
    """
    
    # INPUT SOURCE PATTERNS (HIGH PRIORITY for OWASP Top 10)
    INPUT_SOURCE_PATTERNS = {
        # HTTP Request Parameters (Web vulnerabilities)
        'request.GET', 'request.POST', 'request.args', 'request.form', 
        'request.json', 'request.data', 'request.values', 'request.cookies',
        'request.headers', 'request.files', 'req.query', 'req.body', 
        'req.params', 'req.headers', 'req.cookies',
        
        # Command-line arguments
        'sys.argv', 'process.argv',
        
        # User input functions
        'input', 'raw_input', 'stdin.read', 'stdin.readline',
        
        # File uploads
        'request.FILES', 'werkzeug.FileStorage', 'MultipartFile',
        
        # Environment variables (can be tainted)
        'os.environ', 'os.getenv', 'process.env',
        
        # URL parameters
        'urlparse', 'parse_qs', 'QueryDict',
        
        # Database results (if from user-influenced queries)
        'cursor.fetchone', 'cursor.fetchall', 'cursor.fetchmany'
    }
    
    # DANGEROUS SINKS (Where tainted data causes vulnerabilities)
    DANGEROUS_SINKS = {
        # SQL Injection
        'execute', 'executemany', 'raw', 'cursor.execute', 'connection.execute',
        'db.execute', 'query', 'rawQuery', 'sequelize.query', 'knex.raw',
        
        # Command Injection
        'os.system', 'subprocess.call', 'subprocess.Popen', 'subprocess.run',
        'os.popen', 'eval', 'exec', 'compile', 'child_process.exec',
        'child_process.spawn',
        
        # XSS / Code Injection
        'innerHTML', 'outerHTML', 'document.write', 'document.writeln',
        'render_template_string', 'Markup', 'safe', '__html__',
        
        # Path Traversal
        'open', 'file', 'read', 'write', 'os.path.join', 'Path',
        
        # LDAP Injection
        'search_s', 'search_st', 'search_ext',
        
        # XML Injection
        'parse', 'fromstring', 'XMLParser',
        
        # Deserialization
        'pickle.loads', 'yaml.load', 'json.loads', 'eval'
    }
    
    # SANITIZERS (Taint removal)
    SANITIZERS = {
        'escape', 'quote', 'quote_plus', 'urlencode', 'html.escape',
        'bleach.clean', 'sanitize', 'validate', 'clean', 'strip_tags',
        'escape_string', 'addslashes', 'mysqli_real_escape_string',
        'parameterize', 'prepare', 'bind'
    }
    
    def __init__(self):
        self.node_id_counter = 0
        self.tainted_nodes: Set[str] = set()  # Track which nodes are tainted
        self.input_sources: List[GraphNode] = []  # Track all input sources
        self.dangerous_sinks: List[GraphNode] = []  # Track all dangerous sinks
    
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
        """Process individual node for DFG edges with INPUT TAINT TRACKING."""
        
        # === INPUT SOURCE DETECTION (HIGH PRIORITY) ===
        if self._is_input_source(node):
            # Mark as TAINT_SOURCE
            self._mark_as_tainted(node.id)
            self.input_sources.append(node)
            
            # Create explicit TAINT_SOURCE node
            taint_node_id = f"taint_source_{self.node_id_counter}"
            self.node_id_counter += 1
            
            taint_node = GraphNode(
                id=taint_node_id,
                type=NodeType.TAINT_SOURCE,
                name=f"INPUT_SOURCE: {node.name}",
                value=node.name,
                file=filename,
                line=node.line,
                column=node.column,
                metadata={"input_type": self._classify_input_type(node.name)}
            )
            new_nodes.append(taint_node)
            
            # Link input source to taint node
            dfg_edges.append(GraphEdge(
                from_node=taint_node_id,
                to_node=node.id,
                type=EdgeType.TAINT_FLOW,
                metadata={"taint": "source", "input_pattern": node.name}
            ))
        
        # === DANGEROUS SINK DETECTION ===
        if self._is_dangerous_sink(node):
            self.dangerous_sinks.append(node)
            
            # Mark as SENSITIVE_SINK
            sink_node_id = f"sink_{self.node_id_counter}"
            self.node_id_counter += 1
            
            sink_node = GraphNode(
                id=sink_node_id,
                type=NodeType.SENSITIVE_SINK,
                name=f"SINK: {node.name}",
                value=node.name,
                file=filename,
                line=node.line,
                column=node.column,
                metadata={"sink_type": self._classify_sink_type(node.name)}
            )
            new_nodes.append(sink_node)
            
            # Link node to sink
            dfg_edges.append(GraphEdge(
                from_node=node.id,
                to_node=sink_node_id,
                type=EdgeType.TAINT_FLOW,
                metadata={"taint": "sink", "danger": "high"}
            ))
        
        # === PARAMETERS: Initial definitions (can be tainted if from request) ===
        if node.type == NodeType.PARAMETER and node.name:
            if node.name not in definitions:
                definitions[node.name] = []
            definitions[node.name].append(node.id)
            
            # Check if parameter name suggests it's from user input
            if self._is_likely_user_input_param(node.name):
                self._mark_as_tainted(node.id)
        
        # === ASSIGNMENTS: Track definition and TAINT PROPAGATION ===
        elif node.type == NodeType.ASSIGNMENT and node.name:
            # Find variables used in RHS
            rhs_vars = self._get_rhs_variables(node, graph)
            
            # TAINT PROPAGATION: If any RHS variable is tainted, assignment is tainted
            is_tainted = any(var_id in self.tainted_nodes for var_id in rhs_vars)
            
            if is_tainted:
                self._mark_as_tainted(node.id)
                # Add TAINT_FLOW edge
                for var_id in rhs_vars:
                    if var_id in self.tainted_nodes:
                        dfg_edges.append(GraphEdge(
                            from_node=var_id,
                            to_node=node.id,
                            type=EdgeType.TAINT_FLOW,
                            metadata={"propagation": "assignment"}
                        ))
            
            # Regular DFG tracking
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
        
        # === VARIABLES: Connect to definitions and PROPAGATE TAINT ===
        elif node.type == NodeType.VARIABLE and node.name:
            if node.name in definitions:
                for def_id in definitions[node.name]:
                    # Check if definition is tainted
                    if def_id in self.tainted_nodes:
                        self._mark_as_tainted(node.id)
                        dfg_edges.append(GraphEdge(
                            from_node=def_id,
                            to_node=node.id,
                            type=EdgeType.TAINT_FLOW,
                            metadata={"variable": node.name, "tainted": True}
                        ))
                    else:
                        dfg_edges.append(GraphEdge(
                            from_node=def_id,
                            to_node=node.id,
                            type=EdgeType.DFG_FLOW,
                            metadata={"variable": node.name}
                        ))
        
        # === CALL EXPRESSIONS: Process arguments and TAINT PROPAGATION ===
        elif node.type == NodeType.CALL_EXPRESSION:
            # Check if this is a SANITIZER call
            if self._is_sanitizer(node):
                # Sanitizer removes taint from its arguments
                self._process_sanitizer(node, graph, dfg_edges)
            else:
                # Regular call: propagate taint through arguments
                self._process_call_with_taint(node, graph, definitions, dfg_edges, 
                                            new_nodes, filename, ast_map)
        
        # === RETURN STATEMENTS: Track return values and taint ===
        elif node.type == NodeType.RETURN:
            func_node = self._find_parent_function(node, graph)
            if func_node and func_node.name:
                if func_node.name not in returns:
                    returns[func_node.name] = []
                returns[func_node.name].append(node.id)
                
                # Connect variables in return expression
                self._connect_vars_in_subtree(node.id, node.id, graph, definitions, dfg_edges)
                
                # If return value contains tainted data, mark return as tainted
                return_vars = self._get_subtree_variables(node, graph)
                if any(var_id in self.tainted_nodes for var_id in return_vars):
                    self._mark_as_tainted(node.id)
        
        # === ATTRIBUTE ACCESS: Track obj.attr flows and INPUT SOURCES ===
        elif node.type in (NodeType.ATTRIBUTE_ACCESS, NodeType.ATTRIBUTE):
            # Check if this is an input source (e.g., request.GET, request.json)
            if self._is_input_source(node):
                self._mark_as_tainted(node.id)
                self.input_sources.append(node)
            
            self._process_attribute_access(node, graph, definitions, attributes, dfg_edges)
        
        # === SUBSCRIPTS: Can be input sources (sys.argv[1]) ===
        elif node.type == NodeType.SUBSCRIPT:
            if self._is_input_source(node):
                self._mark_as_tainted(node.id)
                self.input_sources.append(node)
    
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
    
    def _is_input_source(self, node: GraphNode) -> bool:
        """Check if node represents an input source."""
        if not node.name:
            return False
        
        node_name = node.name.lower()
        
        # Check against all INPUT_SOURCE_PATTERNS
        for pattern in self.INPUT_SOURCE_PATTERNS:
            if pattern.lower() in node_name:
                return True
        
        # Additional checks for common patterns
        # request.GET['key'], request.POST['key'], sys.argv[1], etc.
        if any(x in node_name for x in ['request.', 'req.', 'sys.argv', 'input(', 'raw_input(']):
            return True
        
        return False
    
    def _is_dangerous_sink(self, node: GraphNode) -> bool:
        """Check if node represents a dangerous sink."""
        if not node.name:
            return False
        
        node_name = node.name.lower()
        
        # Check against all DANGEROUS_SINKS
        for sink in self.DANGEROUS_SINKS:
            if sink.lower() in node_name:
                return True
        
        return False
    
    def _is_sanitizer(self, node: GraphNode) -> bool:
        """Check if node is a sanitization function."""
        if not node.name:
            return False
        
        node_name = node.name.lower()
        
        # Check against all SANITIZERS
        for sanitizer in self.SANITIZERS:
            if sanitizer.lower() in node_name:
                return True
        
        return False
    
    def _is_likely_user_input_param(self, param_name: str) -> bool:
        """Check if parameter name suggests user input."""
        user_input_indicators = [
            'request', 'req', 'input', 'data', 'user', 'query', 
            'body', 'params', 'args', 'form', 'post', 'get'
        ]
        param_lower = param_name.lower()
        return any(indicator in param_lower for indicator in user_input_indicators)
    
    def _classify_input_type(self, input_name: str) -> str:
        """Classify the type of input source."""
        name_lower = input_name.lower()
        
        if 'request.get' in name_lower or 'req.query' in name_lower:
            return 'HTTP_GET'
        elif 'request.post' in name_lower or 'request.form' in name_lower:
            return 'HTTP_POST'
        elif 'request.json' in name_lower or 'req.body' in name_lower:
            return 'HTTP_JSON'
        elif 'request.files' in name_lower:
            return 'FILE_UPLOAD'
        elif 'request.cookies' in name_lower:
            return 'COOKIE'
        elif 'request.headers' in name_lower:
            return 'HTTP_HEADER'
        elif 'sys.argv' in name_lower:
            return 'CLI_ARGUMENT'
        elif 'input(' in name_lower or 'raw_input(' in name_lower:
            return 'USER_INPUT'
        elif 'os.environ' in name_lower:
            return 'ENVIRONMENT'
        else:
            return 'UNKNOWN'
    
    def _classify_sink_type(self, sink_name: str) -> str:
        """Classify the type of dangerous sink."""
        name_lower = sink_name.lower()
        
        if any(x in name_lower for x in ['execute', 'cursor.execute', 'query']):
            return 'SQL_INJECTION'
        elif any(x in name_lower for x in ['os.system', 'subprocess', 'exec', 'eval']):
            return 'COMMAND_INJECTION'
        elif any(x in name_lower for x in ['innerhtml', 'document.write', 'render']):
            return 'XSS'
        elif any(x in name_lower for x in ['open', 'read', 'write']):
            return 'PATH_TRAVERSAL'
        elif any(x in name_lower for x in ['pickle', 'yaml', 'deserialize']):
            return 'DESERIALIZATION'
        else:
            return 'UNKNOWN'
    
    def _mark_as_tainted(self, node_id: str):
        """Mark a node as tainted."""
        self.tainted_nodes.add(node_id)
    
    def _get_rhs_variables(self, assignment_node: GraphNode, graph: SemanticGraph) -> List[str]:
        """Get all variable IDs used on the right-hand side of an assignment."""
        var_ids = []
        
        # Get children of assignment node
        for edge in graph.edges:
            if edge.from_node == assignment_node.id and edge.type == EdgeType.AST_CHILD:
                child_node = next((n for n in graph.nodes if n.id == edge.to_node), None)
                if child_node and child_node.type == NodeType.VARIABLE:
                    var_ids.append(child_node.id)
        
        return var_ids
    
    def _get_subtree_variables(self, node: GraphNode, graph: SemanticGraph) -> List[str]:
        """Get all variable IDs in a node's subtree."""
        var_ids = []
        visited = set()
        
        def traverse(current_id: str):
            if current_id in visited:
                return
            visited.add(current_id)
            
            current_node = next((n for n in graph.nodes if n.id == current_id), None)
            if current_node and current_node.type == NodeType.VARIABLE:
                var_ids.append(current_id)
            
            # Traverse children
            for edge in graph.edges:
                if edge.from_node == current_id and edge.type == EdgeType.AST_CHILD:
                    traverse(edge.to_node)
        
        traverse(node.id)
        return var_ids
    
    def _process_sanitizer(self, sanitizer_node: GraphNode, graph: SemanticGraph, 
                          dfg_edges: List[GraphEdge]):
        """Process sanitizer call - removes taint from arguments."""
        # Find arguments to the sanitizer
        for edge in graph.edges:
            if edge.from_node == sanitizer_node.id and edge.type == EdgeType.AST_CHILD:
                arg_node = next((n for n in graph.nodes if n.id == edge.to_node), None)
                if arg_node:
                    # Get variables in argument
                    arg_vars = self._get_subtree_variables(arg_node, graph)
                    
                    # Create SANITIZATION edge
                    for var_id in arg_vars:
                        if var_id in self.tainted_nodes:
                            dfg_edges.append(GraphEdge(
                                from_node=var_id,
                                to_node=sanitizer_node.id,
                                type=EdgeType.DFG_FLOW,
                                metadata={
                                    "sanitized": True,
                                    "sanitizer": sanitizer_node.name
                                }
                            ))
    
    def _process_call_with_taint(self, call_node: GraphNode, graph: SemanticGraph,
                                 definitions: Dict[str, List[str]],
                                 dfg_edges: List[GraphEdge],
                                 new_nodes: List[GraphNode],
                                 filename: str,
                                 ast_map: Dict[int, List[ast.AST]]):
        """Process function call with taint propagation."""
        # Check if this call has f-strings or string operations in arguments
        if call_node.line in self.stmt_map:
            stmt = self.stmt_map[call_node.line]
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                self._process_call_arguments(stmt.value, call_node, graph, definitions,
                                            dfg_edges, new_nodes, filename)
            elif isinstance(stmt, ast.Call):
                self._process_call_arguments(stmt, call_node, graph, definitions,
                                            dfg_edges, new_nodes, filename)
        
        # Process regular argument flows with taint
        self._process_call_expression(call_node, graph, definitions, dfg_edges, 
                                     ast_map, new_nodes, filename)
        
        # TAINT PROPAGATION: If any argument is tainted, return value is tainted
        has_tainted_arg = False
        for edge in graph.edges:
            if edge.from_node == call_node.id and edge.type == EdgeType.AST_CHILD:
                arg_node = next((n for n in graph.nodes if n.id == edge.to_node), None)
                if arg_node:
                    arg_vars = self._get_subtree_variables(arg_node, graph)
                    if any(var_id in self.tainted_nodes for var_id in arg_vars):
                        has_tainted_arg = True
                        break
        
        if has_tainted_arg:
            self._mark_as_tainted(call_node.id)
    
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
