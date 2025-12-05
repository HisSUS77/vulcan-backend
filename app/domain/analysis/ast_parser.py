"""
UPGRADED AST Parser with Tree-Sitter for Multi-Language Support
Supports: Python, JavaScript, TypeScript with proper node extraction
"""

from typing import Optional, List, Tuple, Any
from app.schemas.graph import GraphNode, GraphEdge, SemanticGraph
from app.enums.node_type import NodeType
from app.enums.edge_type import EdgeType
import ast
import re

# Tree-sitter imports (install: pip install tree-sitter tree-sitter-python tree-sitter-javascript tree-sitter-typescript)
try:
    from tree_sitter import Language, Parser
    import tree_sitter_python as tspython
    import tree_sitter_javascript as tsjavascript
    import tree_sitter_typescript as tstypescript
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Parser = Any  # Type hint placeholder
    Language = Any  # Type hint placeholder
    print("[WARNING] tree-sitter not installed. JS/TS parsing will be limited.")


class ASTParser:
    """
    Multi-language AST parser with enhanced vulnerability detection.
    Supports Python (native ast), JavaScript/TypeScript (tree-sitter).
    """
    
    def __init__(self, language: str = "python"):
        self.language = language.lower()
        self.node_counter = 0
        
        # Initialize tree-sitter parsers if available
        if TREE_SITTER_AVAILABLE:
            self.js_parser = self._init_js_parser()
            self.ts_parser = self._init_ts_parser()
        else:
            self.js_parser = None
            self.ts_parser = None
    
    def _init_js_parser(self) -> Optional[Any]:
        """Initialize JavaScript parser with compatibility for old and new tree-sitter API."""
        try:
            from tree_sitter_javascript import language as js_language
            from tree_sitter import Language
            parser = Parser()
            parser.language = Language(js_language())
            return parser
        except Exception as e:
            print(f"[WARNING] Failed to init JS parser: {e}")
            return None
    
    def _init_ts_parser(self) -> Optional[Any]:
        """Initialize TypeScript parser with compatibility for old and new tree-sitter API."""
        try:
            from tree_sitter_typescript import language_typescript
            from tree_sitter import Language
            parser = Parser()
            parser.language = Language(language_typescript())
            return parser
        except Exception as e:
            print(f"[WARNING] Failed to init TS parser: {e}")
            return None
    
    def parse(self, code: str, filename: str = "unknown") -> SemanticGraph:
        """Parse source code into AST nodes and edges."""
        if self.language == "python":
            nodes, edges = self._parse_python(code, filename)
        elif self.language in ("javascript", "js"):
            nodes, edges = self._parse_javascript(code, filename)
        elif self.language in ("typescript", "ts"):
            nodes, edges = self._parse_typescript(code, filename)
        else:
            # Unsupported language - return minimal graph
            nodes = [GraphNode(
                id="file_0",
                type=NodeType.FILE,
                name=filename,
                file=filename,
                line=1,
                column=0
            )]
            edges = []
        
        return SemanticGraph(nodes=nodes, edges=edges)
    
    # =====================================================================
    # PYTHON PARSING (Enhanced)
    # =====================================================================
    
    def _parse_python(self, code: str, filename: str):
        """Parse Python with enhanced f-string, .format(), and ORM detection."""
        # Pre-process: normalize comments
        code = self._normalize_code(code)
        
        try:
            tree = ast.parse(code, filename=filename)
        except SyntaxError as e:
            print(f"[ERROR] Python syntax error in {filename}: {e}")
            return self._create_error_graph(filename)
        
        # Create file root
        file_node_id = self._next_id()
        nodes = [GraphNode(
            id=file_node_id,
            type=NodeType.FILE,
            name=filename,
            file=filename,
            line=1,
            column=0
        )]
        edges = []
        
        # Parse each top-level node
        for child in tree.body:
            child_nodes, child_edges = self._parse_ast_node(child, file_node_id, filename)
            nodes.extend(child_nodes)
            edges.extend(child_edges)
        
        return nodes, edges
    
    def _parse_ast_node(self, node, parent_id: str, filename: str) -> Tuple[List[GraphNode], List[GraphEdge]]:
        """Recursively parse Python AST node with enhanced detection."""
        node_id = self._next_id()
        nodes = []
        edges = []
        
        # ==================== FUNCTION DEFINITION ====================
        if isinstance(node, ast.FunctionDef):
            func_node = GraphNode(
                id=node_id,
                type=NodeType.FUNCTION,
                name=node.name,
                file=filename,
                line=node.lineno,
                column=node.col_offset,
                metadata={
                    "is_async": False,
                    "decorators": [self._get_full_name(d) for d in node.decorator_list]
                }
            )
            nodes.append(func_node)
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
            
            # Parse parameters
            for arg in node.args.args:
                param_nodes, param_edges = self._parse_parameter(arg, node_id, filename, node.lineno)
                nodes.extend(param_nodes)
                edges.extend(param_edges)
            
            # Parse body
            for stmt in node.body:
                child_nodes, child_edges = self._parse_ast_node(stmt, node_id, filename)
                nodes.extend(child_nodes)
                edges.extend(child_edges)
        
        # ==================== ASYNC FUNCTION ====================
        elif isinstance(node, ast.AsyncFunctionDef):
            func_node = GraphNode(
                id=node_id,
                type=NodeType.FUNCTION,
                name=node.name,
                file=filename,
                line=node.lineno,
                column=node.col_offset,
                metadata={
                    "is_async": True,
                    "decorators": [self._get_full_name(d) for d in node.decorator_list]
                }
            )
            nodes.append(func_node)
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
            
            # Parse parameters and body
            for arg in node.args.args:
                param_nodes, param_edges = self._parse_parameter(arg, node_id, filename, node.lineno)
                nodes.extend(param_nodes)
                edges.extend(param_edges)
            
            for stmt in node.body:
                child_nodes, child_edges = self._parse_ast_node(stmt, node_id, filename)
                nodes.extend(child_nodes)
                edges.extend(child_edges)
        
        # ==================== ASSIGNMENT (Enhanced for f-strings) ====================
        elif isinstance(node, ast.Assign):
            var_name = self._extract_target_name(node.targets[0]) if node.targets else None
            
            assign_node = GraphNode(
                id=node_id,
                type=NodeType.ASSIGNMENT,
                name=var_name,
                file=filename,
                line=node.lineno,
                column=node.col_offset
            )
            nodes.append(assign_node)
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
            
            # Parse value (handles f-strings, .format(), concatenation)
            child_nodes, child_edges = self._parse_ast_node(node.value, node_id, filename)
            nodes.extend(child_nodes)
            edges.extend(child_edges)
        
        # ==================== F-STRING (JoinedStr) ====================
        elif isinstance(node, ast.JoinedStr):
            fstring_node = GraphNode(
                id=node_id,
                type=NodeType.FSTRING,  # Use FSTRING for Python f-strings
                name="f-string",
                file=filename,
                line=node.lineno,
                column=node.col_offset,
                metadata={"is_fstring": True}
            )
            nodes.append(fstring_node)
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
            
            # Parse each embedded expression
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    expr_nodes, expr_edges = self._parse_ast_node(value.value, node_id, filename)
                    nodes.extend(expr_nodes)
                    edges.extend(expr_edges)
        
        # ==================== VARIABLE REFERENCE ====================
        elif isinstance(node, ast.Name):
            var_node = GraphNode(
                id=node_id,
                type=NodeType.VARIABLE,
                name=node.id,
                value=node.id,
                file=filename,
                line=node.lineno,
                column=node.col_offset
            )
            nodes.append(var_node)
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        
        # ==================== SUBSCRIPT (Array/Dict Access) ====================
        elif isinstance(node, ast.Subscript):
            subscript_name = self._get_full_name(node)
            
            subscript_node = GraphNode(
                id=node_id,
                type=NodeType.SUBSCRIPT,
                name=subscript_name,
                file=filename,
                line=node.lineno,
                column=node.col_offset
            )
            nodes.append(subscript_node)
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
            
            # Parse value and slice
            child_nodes, child_edges = self._parse_ast_node(node.value, node_id, filename)
            nodes.extend(child_nodes)
            edges.extend(child_edges)
        
        # ==================== FUNCTION CALL (Enhanced) ====================
        elif isinstance(node, ast.Call):
            call_name = self._get_full_name(node.func)
            
            call_node = GraphNode(
                id=node_id,
                type=NodeType.CALL_EXPRESSION,
                name=call_name,
                file=filename,
                line=node.lineno,
                column=node.col_offset,
                metadata={
                    "is_method_call": isinstance(node.func, ast.Attribute),
                    "is_dynamic": self._is_dynamic_call(node)
                }
            )
            nodes.append(call_node)
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
            
            # Parse arguments
            for arg in node.args:
                child_nodes, child_edges = self._parse_ast_node(arg, node_id, filename)
                nodes.extend(child_nodes)
                edges.extend(child_edges)
            
            # Parse keyword arguments (for .format(), ORM filters)
            for keyword in node.keywords:
                child_nodes, child_edges = self._parse_ast_node(keyword.value, node_id, filename)
                nodes.extend(child_nodes)
                edges.extend(child_edges)
        
        # ==================== AWAIT EXPRESSION ====================
        elif isinstance(node, ast.Await):
            await_node = GraphNode(
                id=node_id,
                type=NodeType.AWAIT_EXPRESSION,
                file=filename,
                line=node.lineno,
                column=node.col_offset
            )
            nodes.append(await_node)
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
            
            # Parse awaited expression
            child_nodes, child_edges = self._parse_ast_node(node.value, node_id, filename)
            nodes.extend(child_nodes)
            edges.extend(child_edges)
        
        # ==================== ATTRIBUTE ACCESS ====================
        elif isinstance(node, ast.Attribute):
            attr_name = self._get_full_name(node)
            attr_node = GraphNode(
                id=node_id,
                type=NodeType.MEMBER_EXPRESSION,
                name=attr_name,
                file=filename,
                line=node.lineno,
                column=node.col_offset
            )
            nodes.append(attr_node)
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
            
            # Parse base object
            child_nodes, child_edges = self._parse_ast_node(node.value, node_id, filename)
            nodes.extend(child_nodes)
            edges.extend(child_edges)
        
        # ==================== RETURN STATEMENT ====================
        elif isinstance(node, ast.Return):
            return_node = GraphNode(
                id=node_id,
                type=NodeType.RETURN,
                file=filename,
                line=node.lineno,
                column=node.col_offset
            )
            nodes.append(return_node)
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
            
            if node.value:
                child_nodes, child_edges = self._parse_ast_node(node.value, node_id, filename)
                nodes.extend(child_nodes)
                edges.extend(child_edges)
        
        # ==================== BINARY OPERATION ====================
        elif isinstance(node, ast.BinOp):
            binop_node = GraphNode(
                id=node_id,
                type=NodeType.BINARY_OP,
                file=filename,
                line=node.lineno,
                column=node.col_offset,
                metadata={"operator": node.op.__class__.__name__}
            )
            nodes.append(binop_node)
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
            
            # Parse left and right
            left_nodes, left_edges = self._parse_ast_node(node.left, node_id, filename)
            nodes.extend(left_nodes)
            edges.extend(left_edges)
            
            right_nodes, right_edges = self._parse_ast_node(node.right, node_id, filename)
            nodes.extend(right_nodes)
            edges.extend(right_edges)
        
        # ==================== EXPRESSION WRAPPER ====================
        elif isinstance(node, ast.Expr):
            return self._parse_ast_node(node.value, parent_id, filename)
        
        # ==================== CONTROL FLOW ====================
        # IF STATEMENT with metadata for CFG builder
        elif isinstance(node, ast.If):
            # Create IF_STATEMENT node
            if_node = GraphNode(
                id=node_id,
                type=NodeType.IF_STATEMENT,
                file=filename,
                line=node.lineno,
                column=node.col_offset,
                metadata={
                    "then_block_start": node.body[0].lineno if node.body else None,
                    "then_block_end": node.body[-1].end_lineno if node.body and hasattr(node.body[-1], 'end_lineno') else (node.body[-1].lineno if node.body else None),
                    "else_block_start": node.orelse[0].lineno if node.orelse else None,
                    "else_block_end": node.orelse[-1].end_lineno if node.orelse and hasattr(node.orelse[-1], 'end_lineno') else (node.orelse[-1].lineno if node.orelse else None),
                    "has_else": len(node.orelse) > 0
                }
            )
            nodes.append(if_node)
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
            
            # Parse condition
            cond_nodes, cond_edges = self._parse_ast_node(node.test, node_id, filename)
            nodes.extend(cond_nodes)
            edges.extend(cond_edges)
            
            # Parse then block
            for stmt in node.body:
                stmt_nodes, stmt_edges = self._parse_ast_node(stmt, node_id, filename)
                nodes.extend(stmt_nodes)
                edges.extend(stmt_edges)
            
            # Parse else block
            for stmt in node.orelse:
                stmt_nodes, stmt_edges = self._parse_ast_node(stmt, node_id, filename)
                nodes.extend(stmt_nodes)
                edges.extend(stmt_edges)
        
        # TRY STATEMENT with metadata for exception flow
        elif isinstance(node, ast.Try):
            try_node = GraphNode(
                id=node_id,
                type=NodeType.TRY_STATEMENT,
                file=filename,
                line=node.lineno,
                column=node.col_offset,
                metadata={
                    "try_block_start": node.body[0].lineno if node.body else None,
                    "try_block_end": node.body[-1].end_lineno if node.body and hasattr(node.body[-1], 'end_lineno') else (node.body[-1].lineno if node.body else None),
                    "has_except": len(node.handlers) > 0,
                    "has_finally": len(node.finalbody) > 0,
                    "except_handlers": [
                        {
                            "start": handler.body[0].lineno if handler.body else None,
                            "end": handler.body[-1].end_lineno if handler.body and hasattr(handler.body[-1], 'end_lineno') else (handler.body[-1].lineno if handler.body else None),
                            "exception_type": self._get_full_name(handler.type) if handler.type else "Exception"
                        }
                        for handler in node.handlers
                    ],
                    "finally_block_start": node.finalbody[0].lineno if node.finalbody else None,
                    "finally_block_end": node.finalbody[-1].end_lineno if node.finalbody and hasattr(node.finalbody[-1], 'end_lineno') else (node.finalbody[-1].lineno if node.finalbody else None)
                }
            )
            nodes.append(try_node)
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
            
            # Parse try block
            for stmt in node.body:
                stmt_nodes, stmt_edges = self._parse_ast_node(stmt, node_id, filename)
                nodes.extend(stmt_nodes)
                edges.extend(stmt_edges)
            
            # Parse except handlers
            for handler in node.handlers:
                handler_id = self._next_id()
                handler_node = GraphNode(
                    id=handler_id,
                    type=NodeType.EXCEPT_HANDLER,
                    name=self._get_full_name(handler.type) if handler.type else "Exception",
                    file=filename,
                    line=handler.lineno,
                    column=handler.col_offset
                )
                nodes.append(handler_node)
                edges.append(GraphEdge(from_node=node_id, to_node=handler_id, type=EdgeType.AST_CHILD))
                
                for stmt in handler.body:
                    stmt_nodes, stmt_edges = self._parse_ast_node(stmt, handler_id, filename)
                    nodes.extend(stmt_nodes)
                    edges.extend(stmt_edges)
            
            # Parse finally block
            for stmt in node.finalbody:
                stmt_nodes, stmt_edges = self._parse_ast_node(stmt, node_id, filename)
                nodes.extend(stmt_nodes)
                edges.extend(stmt_edges)
        
        # FOR STATEMENT with metadata for loop flow
        elif isinstance(node, ast.For):
            for_node = GraphNode(
                id=node_id,
                type=NodeType.FOR_STATEMENT,
                name=self._extract_target_name(node.target) if node.target else None,
                file=filename,
                line=node.lineno,
                column=node.col_offset,
                metadata={
                    "loop_block_start": node.body[0].lineno if node.body else None,
                    "loop_block_end": node.body[-1].end_lineno if node.body and hasattr(node.body[-1], 'end_lineno') else (node.body[-1].lineno if node.body else None),
                    "has_else": len(node.orelse) > 0
                }
            )
            nodes.append(for_node)
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
            
            # Parse iterator
            iter_nodes, iter_edges = self._parse_ast_node(node.iter, node_id, filename)
            nodes.extend(iter_nodes)
            edges.extend(iter_edges)
            
            # Parse loop body
            for stmt in node.body:
                stmt_nodes, stmt_edges = self._parse_ast_node(stmt, node_id, filename)
                nodes.extend(stmt_nodes)
                edges.extend(stmt_edges)
            
            # Parse else block
            for stmt in node.orelse:
                stmt_nodes, stmt_edges = self._parse_ast_node(stmt, node_id, filename)
                nodes.extend(stmt_nodes)
                edges.extend(stmt_edges)
        
        # WHILE STATEMENT with metadata for loop flow
        elif isinstance(node, ast.While):
            while_node = GraphNode(
                id=node_id,
                type=NodeType.WHILE_STATEMENT,
                file=filename,
                line=node.lineno,
                column=node.col_offset,
                metadata={
                    "loop_block_start": node.body[0].lineno if node.body else None,
                    "loop_block_end": node.body[-1].end_lineno if node.body and hasattr(node.body[-1], 'end_lineno') else (node.body[-1].lineno if node.body else None),
                    "has_else": len(node.orelse) > 0
                }
            )
            nodes.append(while_node)
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
            
            # Parse condition
            cond_nodes, cond_edges = self._parse_ast_node(node.test, node_id, filename)
            nodes.extend(cond_nodes)
            edges.extend(cond_edges)
            
            # Parse loop body
            for stmt in node.body:
                stmt_nodes, stmt_edges = self._parse_ast_node(stmt, node_id, filename)
                nodes.extend(stmt_nodes)
                edges.extend(stmt_edges)
            
            # Parse else block
            for stmt in node.orelse:
                stmt_nodes, stmt_edges = self._parse_ast_node(stmt, node_id, filename)
                nodes.extend(stmt_nodes)
                edges.extend(stmt_edges)
        
        # BREAK and CONTINUE statements
        elif isinstance(node, ast.Break):
            break_node = GraphNode(
                id=node_id,
                type=NodeType.BREAK_STATEMENT,
                file=filename,
                line=node.lineno,
                column=node.col_offset
            )
            nodes.append(break_node)
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        
        elif isinstance(node, ast.Continue):
            continue_node = GraphNode(
                id=node_id,
                type=NodeType.CONTINUE_STATEMENT,
                file=filename,
                line=node.lineno,
                column=node.col_offset
            )
            nodes.append(continue_node)
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        
        # ==================== LITERALS ====================
        elif isinstance(node, (ast.Str, ast.Constant)):
            const_node = GraphNode(
                id=node_id,
                type=NodeType.LITERAL,
                value=getattr(node, 'value', getattr(node, 's', None)),
                file=filename,
                line=getattr(node, 'lineno', 0),
                column=getattr(node, 'col_offset', 0)
            )
            nodes.append(const_node)
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        
        # ==================== UNKNOWN ====================
        else:
            unknown_node = GraphNode(
                id=node_id,
                type=NodeType.UNKNOWN,
                file=filename,
                line=getattr(node, 'lineno', 0),
                column=getattr(node, 'col_offset', 0),
                metadata={"ast_type": type(node).__name__}
            )
            nodes.append(unknown_node)
            if parent_id:
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        
        return nodes, edges
    
    # =====================================================================
    # JAVASCRIPT/TYPESCRIPT PARSING (Tree-Sitter)
    # =====================================================================
    
    def _parse_javascript(self, code: str, filename: str) -> Tuple[List[GraphNode], List[GraphEdge]]:
        """Parse JavaScript using tree-sitter."""
        if not self.js_parser:
            print("[ERROR] JS parser not available. Install tree-sitter.")
            return self._create_error_graph(filename)
        
        tree = self.js_parser.parse(bytes(code, "utf8"))
        return self._parse_treesitter_node(tree.root_node, None, filename)
    
    def _parse_typescript(self, code: str, filename: str) -> Tuple[List[GraphNode], List[GraphEdge]]:
        """Parse TypeScript using tree-sitter."""
        if not self.ts_parser:
            print("[ERROR] TS parser not available. Install tree-sitter.")
            return self._create_error_graph(filename)
        
        tree = self.ts_parser.parse(bytes(code, "utf8"))
        return self._parse_treesitter_node(tree.root_node, None, filename)
    
    def _parse_treesitter_node(self, ts_node, parent_id: Optional[str], filename: str) -> Tuple[List[GraphNode], List[GraphEdge]]:
        """Parse tree-sitter node recursively."""
        node_id = self._next_id()
        nodes = []
        edges = []
        
        node_type = ts_node.type
        start_line = ts_node.start_point[0] + 1
        start_col = ts_node.start_point[1]
        
        # Map tree-sitter types to our NodeType
        graph_node_type = self._map_js_node_type(node_type)
        
        # Extract node text for names/values
        node_text = ts_node.text.decode('utf8') if ts_node.text else ""
        
        # Create GraphNode
        graph_node = GraphNode(
            id=node_id,
            type=graph_node_type,
            name=self._extract_js_name(ts_node, node_text),
            value=node_text if len(node_text) < 100 else None,
            file=filename,
            line=start_line,
            column=start_col,
            metadata={"ts_type": node_type}
        )
        
        nodes.append(graph_node)
        
        if parent_id:
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        
        # Parse children recursively
        for child in ts_node.children:
            child_nodes, child_edges = self._parse_treesitter_node(child, node_id, filename)
            nodes.extend(child_nodes)
            edges.extend(child_edges)
        
        return nodes, edges
    
    def _map_js_node_type(self, ts_type: str) -> NodeType:
        """Map tree-sitter node types to our NodeType enum."""
        mapping = {
            "program": NodeType.FILE,
            "function_declaration": NodeType.FUNCTION,
            "arrow_function": NodeType.FUNCTION,
            "function": NodeType.FUNCTION,
            "method_definition": NodeType.FUNCTION,
            "call_expression": NodeType.CALL_EXPRESSION,
            "member_expression": NodeType.MEMBER_EXPRESSION,
            "template_string": NodeType.TEMPLATE_LITERAL,
            "template_substitution": NodeType.TEMPLATE_LITERAL,
            "identifier": NodeType.VARIABLE,
            "variable_declarator": NodeType.ASSIGNMENT,
            "assignment_expression": NodeType.ASSIGNMENT,
            "return_statement": NodeType.RETURN,
            "await_expression": NodeType.AWAIT_EXPRESSION,
            "binary_expression": NodeType.BINARY_OP,
            "string": NodeType.LITERAL,
            "number": NodeType.LITERAL,
            "jsx_element": NodeType.JSX_ELEMENT,
            "jsx_expression": NodeType.JSX_ELEMENT,
        }
        return mapping.get(ts_type, NodeType.UNKNOWN)
    
    def _extract_js_name(self, ts_node, text: str) -> Optional[str]:
        """Extract meaningful name from JS/TS node."""
        node_type = ts_node.type
        
        if node_type == "identifier":
            return text
        elif node_type in ("function_declaration", "method_definition"):
            for child in ts_node.children:
                if child.type == "identifier":
                    return child.text.decode('utf8')
        elif node_type == "call_expression":
            for child in ts_node.children:
                if child.type in ("identifier", "member_expression"):
                    return child.text.decode('utf8')
        
        return None
    
    # =====================================================================
    # HELPER METHODS
    # =====================================================================
    
    def _normalize_code(self, code: str) -> str:
        """Normalize code (convert // to # for Python)."""
        lines = code.split('\n')
        cleaned = []
        for line in lines:
            stripped = line.lstrip()
            if stripped.startswith('//'):
                cleaned.append(line.replace('//', '#', 1))
            else:
                cleaned.append(line)
        return '\n'.join(cleaned)
    
    def _parse_parameter(self, arg, parent_id: str, filename: str, lineno: int) -> Tuple[List[GraphNode], List[GraphEdge]]:
        """Parse function parameter."""
        param_id = self._next_id()
        param_node = GraphNode(
            id=param_id,
            type=NodeType.PARAMETER,
            name=arg.arg,
            value=arg.arg,
            file=filename,
            line=lineno,
            column=getattr(arg, 'col_offset', 0)
        )
        edge = GraphEdge(from_node=parent_id, to_node=param_id, type=EdgeType.AST_CHILD)
        return [param_node], [edge]
    
    def _extract_target_name(self, target) -> Optional[str]:
        """Extract variable name from assignment target."""
        if isinstance(target, ast.Name):
            return target.id
        elif isinstance(target, ast.Attribute):
            return self._get_full_name(target)
        elif isinstance(target, ast.Subscript):
            return self._get_full_name(target)
        return None
    
    def _is_dynamic_call(self, call_node: ast.Call) -> bool:
        """Check if call is dynamic (e.g., eval, exec, compile)."""
        dangerous_calls = {'eval', 'exec', 'compile', '__import__'}
        call_name = self._get_full_name(call_node.func)
        return call_name in dangerous_calls if call_name else False
    
    def _get_full_name(self, node) -> Optional[str]:
        """Extract full qualified name from AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            value_name = self._get_full_name(node.value)
            return f"{value_name}.{node.attr}" if value_name else node.attr
        elif isinstance(node, ast.Subscript):
            return self._get_full_name(node.value)
        elif isinstance(node, ast.Call):
            return self._get_full_name(node.func)
        return None
    
    def _create_error_graph(self, filename: str) -> Tuple[List[GraphNode], List[GraphEdge]]:
        """Create minimal error graph."""
        return [GraphNode(
            id=self._next_id(),
            type=NodeType.FILE,
            name=filename,
            file=filename,
            line=1,
            column=0
        )], []
    
    def _next_id(self) -> str:
        node_id = f"node_{self.node_counter}"
        self.node_counter += 1
        return node_id