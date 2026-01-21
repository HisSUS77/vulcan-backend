"""
Enhanced Multi-Language AST Parser
Supports: Python (full AST), JavaScript/TypeScript (regex-based)
"""
from typing import Optional, Tuple, List
from app.schemas.graph import GraphNode, GraphEdge, SemanticGraph
from app.enums.node_type import NodeType
from app.enums.edge_type import EdgeType
import ast
import re


class ASTParser:
    """
    Enhanced multi-language AST parser.
    - Python: Full AST coverage with all security-critical nodes
    - JavaScript/TypeScript: Regex-based parsing with key constructs
    """
    
    def __init__(self, language: str = "python"):
        self.language = language.lower()
        self.node_counter = 0
    
    def parse(self, code: str, filename: str = "unknown") -> SemanticGraph:
        """Parse source code into AST nodes and edges."""
        if self.language == "python":
            nodes, edges = self._parse_python(code, filename)
        elif self.language in ("javascript", "typescript", "js", "ts"):
            nodes, edges = self._parse_javascript(code, filename)
        else:
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
    
    def _parse_python(self, code: str, filename: str) -> Tuple[List[GraphNode], List[GraphEdge]]:
        """Parse Python with comprehensive AST coverage."""
        # Clean up comment styles
        code = self._normalize_comments(code)
        
        try:
            tree = ast.parse(code, filename=filename)
        except SyntaxError as e:
            print(f"[ERROR] Syntax error in {filename}: {e}")
            return [GraphNode(
                id=self._next_id(),
                type=NodeType.FILE,
                name=filename,
                file=filename,
                line=1,
                column=0
            )], []
        
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
        
        # Parse all top-level statements
        for child in tree.body:
            child_nodes, child_edges = self._parse_python_node(child, file_node_id, filename)
            nodes.extend(child_nodes)
            edges.extend(child_edges)
        
        return nodes, edges
    
    def _parse_python_node(self, node, parent_id: str, filename: str) -> Tuple[List[GraphNode], List[GraphEdge]]:
        """Recursively parse Python AST node with full coverage."""
        nodes, edges = [], []
        node_id = self._next_id()
        
        # IMPORTS (Critical for security - tracks dangerous module imports)
        if isinstance(node, ast.Import):
            for alias in node.names:
                imp_id = self._next_id()
                nodes.append(GraphNode(
                    id=imp_id,
                    type=NodeType.IMPORT,
                    name=alias.name,
                    value=alias.asname or alias.name,
                    file=filename,
                    line=node.lineno,
                    column=node.col_offset
                ))
                edges.append(GraphEdge(from_node=parent_id, to_node=imp_id, type=EdgeType.AST_CHILD))
        
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                imp_id = self._next_id()
                full_name = f"{module}.{alias.name}" if module else alias.name
                nodes.append(GraphNode(
                    id=imp_id,
                    type=NodeType.IMPORT,
                    name=full_name,
                    value=alias.asname or alias.name,
                    file=filename,
                    line=node.lineno,
                    column=node.col_offset
                ))
                edges.append(GraphEdge(from_node=parent_id, to_node=imp_id, type=EdgeType.AST_CHILD))
        
        # CLASS DEFINITIONS
        elif isinstance(node, ast.ClassDef):
            nodes.append(GraphNode(
                id=node_id,
                type=NodeType.CLASS,
                name=node.name,
                file=filename,
                line=node.lineno,
                column=node.col_offset
            ))
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
            
            # Parse decorators, bases, and body
            for decorator in node.decorator_list:
                dec_nodes, dec_edges = self._parse_python_node(decorator, node_id, filename)
                nodes.extend(dec_nodes)
                edges.extend(dec_edges)
            
            for stmt in node.body:
                stmt_nodes, stmt_edges = self._parse_python_node(stmt, node_id, filename)
                nodes.extend(stmt_nodes)
                edges.extend(stmt_edges)
        
        # FUNCTIONS (Regular and Async)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_type = NodeType.ASYNC_FUNCTION if isinstance(node, ast.AsyncFunctionDef) else NodeType.FUNCTION
            nodes.append(GraphNode(
                id=node_id,
                type=func_type,
                name=node.name,
                file=filename,
                line=node.lineno,
                column=node.col_offset
            ))
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
            
            # Parse parameters
            for arg in node.args.args:
                param_id = self._next_id()
                nodes.append(GraphNode(
                    id=param_id,
                    type=NodeType.PARAMETER,
                    name=arg.arg,
                    value=arg.arg,
                    file=filename,
                    line=node.lineno,
                    column=getattr(arg, 'col_offset', 0)
                ))
                edges.append(GraphEdge(from_node=node_id, to_node=param_id, type=EdgeType.AST_CHILD))
            
            # Parse body
            for stmt in node.body:
                stmt_nodes, stmt_edges = self._parse_python_node(stmt, node_id, filename)
                nodes.extend(stmt_nodes)
                edges.extend(stmt_edges)
        
        # LAMBDA
        elif isinstance(node, ast.Lambda):
            nodes.append(GraphNode(
                id=node_id,
                type=NodeType.LAMBDA,
                name="<lambda>",
                file=filename,
                line=node.lineno,
                column=node.col_offset
            ))
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
            body_nodes, body_edges = self._parse_python_node(node.body, node_id, filename)
            nodes.extend(body_nodes)
            edges.extend(body_edges)
        
        # ASSIGNMENTS
        elif isinstance(node, ast.Assign):
            var_name = self._extract_target_name(node.targets[0]) if node.targets else None
            nodes.append(GraphNode(
                id=node_id,
                type=NodeType.ASSIGNMENT,
                name=var_name,
                file=filename,
                line=node.lineno,
                column=node.col_offset
            ))
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
            
            val_nodes, val_edges = self._parse_python_node(node.value, node_id, filename)
            nodes.extend(val_nodes)
            edges.extend(val_edges)
        
        # FUNCTION CALLS
        elif isinstance(node, ast.Call):
            call_name = self._get_full_name(node.func)
            nodes.append(GraphNode(
                id=node_id,
                type=NodeType.CALL_EXPRESSION,
                name=call_name,
                file=filename,
                line=node.lineno,
                column=node.col_offset
            ))
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
            
            for arg in node.args:
                arg_nodes, arg_edges = self._parse_python_node(arg, node_id, filename)
                nodes.extend(arg_nodes)
                edges.extend(arg_edges)
        
        # VARIABLES
        elif isinstance(node, ast.Name):
            nodes.append(GraphNode(
                id=node_id,
                type=NodeType.VARIABLE,
                name=node.id,
                value=node.id,
                file=filename,
                line=node.lineno,
                column=node.col_offset
            ))
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        
        # ATTRIBUTES (obj.attr)
        elif isinstance(node, ast.Attribute):
            attr_name = self._get_full_name(node)
            nodes.append(GraphNode(
                id=node_id,
                type=NodeType.ATTRIBUTE,
                name=attr_name,
                value=node.attr,
                file=filename,
                line=node.lineno,
                column=node.col_offset
            ))
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        
        # SUBSCRIPTS (array access, sys.argv[1])
        elif isinstance(node, ast.Subscript):
            subscript_name = self._get_full_name(node)
            nodes.append(GraphNode(
                id=node_id,
                type=NodeType.SUBSCRIPT,
                name=subscript_name,
                file=filename,
                line=node.lineno,
                column=node.col_offset
            ))
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
            
            val_nodes, val_edges = self._parse_python_node(node.value, node_id, filename)
            nodes.extend(val_nodes)
            edges.extend(val_edges)
        
        # COMPREHENSIONS
        elif isinstance(node, (ast.ListComp, ast.DictComp, ast.SetComp, ast.GeneratorExp)):
            comp_type_map = {
                ast.ListComp: NodeType.LIST_COMP,
                ast.DictComp: NodeType.DICT_COMP,
                ast.SetComp: NodeType.SET_COMP,
                ast.GeneratorExp: NodeType.GENERATOR_EXP
            }
            nodes.append(GraphNode(
                id=node_id,
                type=comp_type_map[type(node)],
                file=filename,
                line=node.lineno,
                column=node.col_offset
            ))
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        
        # EXCEPTION HANDLING
        elif isinstance(node, ast.Try):
            nodes.append(GraphNode(
                id=node_id,
                type=NodeType.TRY,
                file=filename,
                line=node.lineno,
                column=node.col_offset
            ))
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
            
            for stmt in node.body:
                stmt_nodes, stmt_edges = self._parse_python_node(stmt, node_id, filename)
                nodes.extend(stmt_nodes)
                edges.extend(stmt_edges)
            
            for handler in node.handlers:
                handler_id = self._next_id()
                exc_type = self._get_full_name(handler.type) if handler.type else "Exception"
                nodes.append(GraphNode(
                    id=handler_id,
                    type=NodeType.EXCEPT,
                    name=exc_type,
                    value=handler.name,
                    file=filename,
                    line=handler.lineno,
                    column=handler.col_offset
                ))
                edges.append(GraphEdge(from_node=node_id, to_node=handler_id, type=EdgeType.AST_CHILD))
                
                for stmt in handler.body:
                    stmt_nodes, stmt_edges = self._parse_python_node(stmt, handler_id, filename)
                    nodes.extend(stmt_nodes)
                    edges.extend(stmt_edges)
        
        elif isinstance(node, ast.Raise):
            nodes.append(GraphNode(
                id=node_id,
                type=NodeType.RAISE,
                file=filename,
                line=node.lineno,
                column=node.col_offset
            ))
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        
        # RETURN
        elif isinstance(node, ast.Return):
            nodes.append(GraphNode(
                id=node_id,
                type=NodeType.RETURN,
                file=filename,
                line=node.lineno,
                column=node.col_offset
            ))
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
            
            if node.value:
                val_nodes, val_edges = self._parse_python_node(node.value, node_id, filename)
                nodes.extend(val_nodes)
                edges.extend(val_edges)
        
        # CONTROL FLOW
        elif isinstance(node, ast.If):
            for stmt in node.body + node.orelse:
                stmt_nodes, stmt_edges = self._parse_python_node(stmt, parent_id, filename)
                nodes.extend(stmt_nodes)
                edges.extend(stmt_edges)
        
        elif isinstance(node, (ast.For, ast.While)):
            for stmt in node.body + node.orelse:
                stmt_nodes, stmt_edges = self._parse_python_node(stmt, parent_id, filename)
                nodes.extend(stmt_nodes)
                edges.extend(stmt_edges)
        
        # BINARY OPERATIONS
        elif isinstance(node, ast.BinOp):
            nodes.append(GraphNode(
                id=node_id,
                type=NodeType.BINARY_OP,
                file=filename,
                line=node.lineno,
                column=node.col_offset
            ))
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
            
            left_nodes, left_edges = self._parse_python_node(node.left, node_id, filename)
            nodes.extend(left_nodes)
            edges.extend(left_edges)
            
            right_nodes, right_edges = self._parse_python_node(node.right, node_id, filename)
            nodes.extend(right_nodes)
            edges.extend(right_edges)
        
        # AWAIT
        elif isinstance(node, ast.Await):
            nodes.append(GraphNode(
                id=node_id,
                type=NodeType.AWAIT,
                file=filename,
                line=node.lineno,
                column=node.col_offset
            ))
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
            
            val_nodes, val_edges = self._parse_python_node(node.value, node_id, filename)
            nodes.extend(val_nodes)
            edges.extend(val_edges)
        
        # GLOBAL/NONLOCAL
        elif isinstance(node, ast.Global):
            for name in node.names:
                glob_id = self._next_id()
                nodes.append(GraphNode(
                    id=glob_id,
                    type=NodeType.GLOBAL,
                    name=name,
                    file=filename,
                    line=node.lineno,
                    column=node.col_offset
                ))
                edges.append(GraphEdge(from_node=parent_id, to_node=glob_id, type=EdgeType.AST_CHILD))
        
        elif isinstance(node, ast.Nonlocal):
            for name in node.names:
                nonlocal_id = self._next_id()
                nodes.append(GraphNode(
                    id=nonlocal_id,
                    type=NodeType.NONLOCAL,
                    name=name,
                    file=filename,
                    line=node.lineno,
                    column=node.col_offset
                ))
                edges.append(GraphEdge(from_node=parent_id, to_node=nonlocal_id, type=EdgeType.AST_CHILD))
        
        # EXPRESSION WRAPPER
        elif isinstance(node, ast.Expr):
            return self._parse_python_node(node.value, parent_id, filename)
        
        # WITH STATEMENT
        elif isinstance(node, ast.With):
            for stmt in node.body:
                stmt_nodes, stmt_edges = self._parse_python_node(stmt, parent_id, filename)
                nodes.extend(stmt_nodes)
                edges.extend(stmt_edges)
        
        # LITERALS
        elif isinstance(node, (ast.Str, ast.Constant)):
            nodes.append(GraphNode(
                id=node_id,
                type=NodeType.LITERAL,
                value=getattr(node, 'value', getattr(node, 's', None)),
                file=filename,
                line=getattr(node, 'lineno', 0),
                column=getattr(node, 'col_offset', 0)
            ))
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        
        return nodes, edges
    
    def _parse_javascript(self, code: str, filename: str) -> Tuple[List[GraphNode], List[GraphEdge]]:
        """Parse JavaScript/TypeScript using regex patterns."""
        nodes, edges = [], []
        
        file_node_id = self._next_id()
        nodes.append(GraphNode(
            id=file_node_id,
            type=NodeType.FILE,
            name=filename,
            file=filename,
            line=1,
            column=0
        ))
        
        lines = code.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith('//') or stripped.startswith('/*'):
                continue
            
            # IMPORTS
            if 'import' in stripped and 'from' in stripped:
                match = re.match(r'import\s+(?:(\w+)|{([^}]+)})\s+from\s+["\']([^"\']+)["\']', stripped)
                if match:
                    module = match.group(3)
                    imports = match.group(1) or match.group(2)
                    for imp in imports.split(','):
                        imp = imp.strip()
                        imp_id = self._next_id()
                        nodes.append(GraphNode(
                            id=imp_id,
                            type=NodeType.IMPORT,
                            name=f"{module}.{imp}",
                            value=imp,
                            file=filename,
                            line=line_num,
                            column=0
                        ))
                        edges.append(GraphEdge(from_node=file_node_id, to_node=imp_id, type=EdgeType.AST_CHILD))
            
            # REQUIRE
            elif 'require(' in stripped:
                match = re.match(r'(?:const|let|var)\s+(\w+)\s*=\s*require\(["\']([^"\']+)["\']\)', stripped)
                if match:
                    var_name, module = match.groups()
                    imp_id = self._next_id()
                    nodes.append(GraphNode(
                        id=imp_id,
                        type=NodeType.IMPORT,
                        name=module,
                        value=var_name,
                        file=filename,
                        line=line_num,
                        column=0
                    ))
                    edges.append(GraphEdge(from_node=file_node_id, to_node=imp_id, type=EdgeType.AST_CHILD))
            
            # FUNCTION DECLARATIONS
            elif 'function' in stripped:
                match = re.match(r'(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)', stripped)
                if match:
                    func_name, params = match.groups()
                    is_async = 'async' in stripped
                    func_id = self._next_id()
                    nodes.append(GraphNode(
                        id=func_id,
                        type=NodeType.ASYNC_FUNCTION if is_async else NodeType.FUNCTION,
                        name=func_name,
                        file=filename,
                        line=line_num,
                        column=0
                    ))
                    edges.append(GraphEdge(from_node=file_node_id, to_node=func_id, type=EdgeType.AST_CHILD))
                    
                    # Parameters
                    if params:
                        for param in params.split(','):
                            param = param.strip()
                            if param:
                                param_id = self._next_id()
                                nodes.append(GraphNode(
                                    id=param_id,
                                    type=NodeType.PARAMETER,
                                    name=param,
                                    value=param,
                                    file=filename,
                                    line=line_num,
                                    column=0
                                ))
                                edges.append(GraphEdge(from_node=func_id, to_node=param_id, type=EdgeType.AST_CHILD))
            
            # ARROW FUNCTIONS
            elif '=>' in stripped:
                match = re.match(r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>', stripped)
                if match:
                    func_name, params = match.groups()
                    is_async = 'async' in stripped
                    func_id = self._next_id()
                    nodes.append(GraphNode(
                        id=func_id,
                        type=NodeType.ASYNC_FUNCTION if is_async else NodeType.ARROW_FUNCTION,
                        name=func_name,
                        file=filename,
                        line=line_num,
                        column=0
                    ))
                    edges.append(GraphEdge(from_node=file_node_id, to_node=func_id, type=EdgeType.AST_CHILD))
            
            # VARIABLE ASSIGNMENTS
            elif any(keyword in stripped for keyword in ['const', 'let', 'var']):
                match = re.match(r'(?:const|let|var)\s+(\w+)\s*=', stripped)
                if match:
                    var_name = match.group(1)
                    assign_id = self._next_id()
                    nodes.append(GraphNode(
                        id=assign_id,
                        type=NodeType.ASSIGNMENT,
                        name=var_name,
                        file=filename,
                        line=line_num,
                        column=0
                    ))
                    edges.append(GraphEdge(from_node=file_node_id, to_node=assign_id, type=EdgeType.AST_CHILD))
            
            # FUNCTION CALLS (dangerous functions)
            dangerous_calls = ['eval(', 'exec(', 'innerHTML', 'document.write', 'setTimeout', 'setInterval']
            for call in dangerous_calls:
                if call in stripped:
                    call_id = self._next_id()
                    nodes.append(GraphNode(
                        id=call_id,
                        type=NodeType.CALL_EXPRESSION,
                        name=call.rstrip('('),
                        file=filename,
                        line=line_num,
                        column=stripped.index(call)
                    ))
                    edges.append(GraphEdge(from_node=file_node_id, to_node=call_id, type=EdgeType.AST_CHILD))
        
        return nodes, edges
    
    # === HELPER METHODS ===
    
    def _normalize_comments(self, code: str) -> str:
        """Convert // comments to # for Python compatibility."""
        lines = []
        for line in code.split('\n'):
            if line.lstrip().startswith('//'):
                lines.append(line.replace('//', '#', 1))
            else:
                lines.append(line)
        return '\n'.join(lines)
    
    def _get_full_name(self, node) -> str:
        """Extract qualified name (e.g., os.system, sys.argv)."""
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
    
    def _extract_target_name(self, target) -> Optional[str]:
        """Extract variable name from assignment target."""
        if isinstance(target, ast.Name):
            return target.id
        elif isinstance(target, ast.Attribute):
            return self._get_full_name(target)
        return None
    
    def _next_id(self) -> str:
        """Generate unique node ID."""
        node_id = f"node_{self.node_counter}"
        self.node_counter += 1
        return node_id
