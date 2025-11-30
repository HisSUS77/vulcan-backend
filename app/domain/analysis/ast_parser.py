from typing import Optional
from app.schemas.graph import GraphNode, GraphEdge, SemanticGraph
from app.enums.node_type import NodeType
from app.enums.edge_type import EdgeType
import ast


class ASTParser:
    """
    AST parser for multi-language support.
    Currently supports Python with recursive AST traversal.
    """
    
    def __init__(self, language: str = "python"):
        self.language = language
        self.node_counter = 0
    
    def parse(self, code: str, filename: str = "unknown") -> SemanticGraph:
        """Parse source code into AST nodes and edges."""
        if self.language == "python":
            nodes, edges = self._parse_python(code, filename)
        elif self.language in ("javascript", "typescript"):
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
    
    def _parse_python(self, code: str, filename: str):
        """Parse Python code recursively."""
        # Pre-process: Remove common non-Python comment styles that might slip in
        # Replace // comments with # comments
        lines = code.split('\n')
        cleaned_lines = []
        for line in lines:
            # Check if line starts with // (ignoring whitespace)
            stripped = line.lstrip()
            if stripped.startswith('//'):
                # Convert to Python comment
                cleaned_lines.append(line.replace('//', '#', 1))
            else:
                cleaned_lines.append(line)
        code = '\n'.join(cleaned_lines)
        
        try:
            tree = ast.parse(code, filename=filename)
        except SyntaxError as e:
            # Log the syntax error for debugging
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
        
        # Parse each top-level node
        for child in tree.body:
            child_nodes, child_edges = self._parse_ast_node(child, file_node_id, filename)
            nodes.extend(child_nodes)
            edges.extend(child_edges)
        
        return nodes, edges
    
    def _parse_ast_node(self, node, parent_id: str, filename: str) -> tuple[list[GraphNode], list[GraphEdge]]:
        """Recursively parse AST node."""
        node_id = self._next_id()
        nodes = []
        edges = []
        
        if isinstance(node, ast.FunctionDef):
            # Function definition
            func_node = GraphNode(
                id=node_id,
                type=NodeType.FUNCTION,
                name=node.name,
                file=filename,
                line=node.lineno,
                column=node.col_offset
            )
            nodes.append(func_node)
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
            
            # Parse parameters
            for arg in node.args.args:
                param_id = self._next_id()
                param_node = GraphNode(
                    id=param_id,
                    type=NodeType.PARAMETER,
                    name=arg.arg,
                    value=arg.arg,
                    file=filename,
                    line=node.lineno,
                    column=getattr(arg, 'col_offset', 0)
                )
                nodes.append(param_node)
                edges.append(GraphEdge(from_node=node_id, to_node=param_id, type=EdgeType.AST_CHILD))
            
            # Parse body
            for stmt in node.body:
                child_nodes, child_edges = self._parse_ast_node(stmt, node_id, filename)
                nodes.extend(child_nodes)
                edges.extend(child_edges)
        
        elif isinstance(node, ast.Assign):
            # Assignment
            var_name = None
            if node.targets and isinstance(node.targets[0], ast.Name):
                var_name = node.targets[0].id
            
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
            
            # Parse value
            child_nodes, child_edges = self._parse_ast_node(node.value, node_id, filename)
            nodes.extend(child_nodes)
            edges.extend(child_edges)
        
        elif isinstance(node, ast.Name):
            # Variable reference
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
        
        elif isinstance(node, ast.Subscript):
            # Subscript (e.g., sys.argv[1], arr[i])
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
            
            # Parse the value and slice
            child_nodes, child_edges = self._parse_ast_node(node.value, node_id, filename)
            nodes.extend(child_nodes)
            edges.extend(child_edges)
        
        elif isinstance(node, ast.Call):
            # Function call
            call_name = self._get_full_name(node.func)
            
            call_node = GraphNode(
                id=node_id,
                type=NodeType.CALL_EXPRESSION,
                name=call_name,
                file=filename,
                line=node.lineno,
                column=node.col_offset
            )
            nodes.append(call_node)
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
            
            # Parse arguments
            for arg in node.args:
                child_nodes, child_edges = self._parse_ast_node(arg, node_id, filename)
                nodes.extend(child_nodes)
                edges.extend(child_edges)
        
        elif isinstance(node, ast.Return):
            # Return statement
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
        
        elif isinstance(node, ast.BinOp):
            # Binary operation
            binop_node = GraphNode(
                id=node_id,
                type=NodeType.BINARY_OP,
                file=filename,
                line=node.lineno,
                column=node.col_offset
            )
            nodes.append(binop_node)
            edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
            
            # Parse left and right
            child_nodes, child_edges = self._parse_ast_node(node.left, node_id, filename)
            nodes.extend(child_nodes)
            edges.extend(child_edges)
            
            child_nodes, child_edges = self._parse_ast_node(node.right, node_id, filename)
            nodes.extend(child_nodes)
            edges.extend(child_edges)
        
        elif isinstance(node, ast.Expr):
            # Expression statement - skip wrapper, parse value
            return self._parse_ast_node(node.value, parent_id, filename)
        
        elif isinstance(node, ast.If):
            # If statement - parse condition and both branches
            nodes = []
            edges = []
            
            # Parse condition
            cond_nodes, cond_edges = self._parse_ast_node(node.test, parent_id, filename)
            nodes.extend(cond_nodes)
            edges.extend(cond_edges)
            
            # Parse if body
            for stmt in node.body:
                stmt_nodes, stmt_edges = self._parse_ast_node(stmt, parent_id, filename)
                nodes.extend(stmt_nodes)
                edges.extend(stmt_edges)
            
            # Parse else body
            for stmt in node.orelse:
                stmt_nodes, stmt_edges = self._parse_ast_node(stmt, parent_id, filename)
                nodes.extend(stmt_nodes)
                edges.extend(stmt_edges)
        
        elif isinstance(node, ast.Try):
            # Try-except block - parse all parts
            nodes = []
            edges = []
            
            # Parse try body
            for stmt in node.body:
                stmt_nodes, stmt_edges = self._parse_ast_node(stmt, parent_id, filename)
                nodes.extend(stmt_nodes)
                edges.extend(stmt_edges)
            
            # Parse except handlers
            for handler in node.handlers:
                for stmt in handler.body:
                    stmt_nodes, stmt_edges = self._parse_ast_node(stmt, parent_id, filename)
                    nodes.extend(stmt_nodes)
                    edges.extend(stmt_edges)
            
            # Parse else body
            for stmt in node.orelse:
                stmt_nodes, stmt_edges = self._parse_ast_node(stmt, parent_id, filename)
                nodes.extend(stmt_nodes)
                edges.extend(stmt_edges)
            
            # Parse finally body
            for stmt in node.finalbody:
                stmt_nodes, stmt_edges = self._parse_ast_node(stmt, parent_id, filename)
                nodes.extend(stmt_nodes)
                edges.extend(stmt_edges)
        
        elif isinstance(node, (ast.For, ast.While)):
            # Loop statements - parse body
            nodes = []
            edges = []
            
            # Parse loop body
            for stmt in node.body:
                stmt_nodes, stmt_edges = self._parse_ast_node(stmt, parent_id, filename)
                nodes.extend(stmt_nodes)
                edges.extend(stmt_edges)
            
            # Parse else body (for loops can have else)
            for stmt in node.orelse:
                stmt_nodes, stmt_edges = self._parse_ast_node(stmt, parent_id, filename)
                nodes.extend(stmt_nodes)
                edges.extend(stmt_edges)
        
        elif isinstance(node, ast.With):
            # With statement - parse body
            nodes = []
            edges = []
            
            for stmt in node.body:
                stmt_nodes, stmt_edges = self._parse_ast_node(stmt, parent_id, filename)
                nodes.extend(stmt_nodes)
                edges.extend(stmt_edges)
        
        elif isinstance(node, (ast.Str, ast.Constant)):
            # String/constant - create node but don't recurse
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
        
        else:
            # Unknown/unsupported node type
            unknown_node = GraphNode(
                id=node_id,
                type=NodeType.UNKNOWN,
                file=filename,
                line=getattr(node, 'lineno', 0),
                column=getattr(node, 'col_offset', 0)
            )
            nodes.append(unknown_node)
            if parent_id:
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        
        return nodes, edges
    
    def _parse_javascript(self, code: str, filename: str) -> tuple[list[GraphNode], list[GraphEdge]]:
        """Simplified JS/TS parsing."""
        file_node = GraphNode(
            id=self._next_id(),
            type=NodeType.FILE,
            name=filename,
            file=filename,
            line=1,
            column=0
        )
        return [file_node], []
    
    def _get_full_name(self, node) -> str:
        """
        Extract full qualified name from an AST node.
        Examples:
        - ast.Name("system") -> "system"
        - ast.Attribute(value=Name("os"), attr="system") -> "os.system"
        - ast.Attribute(value=Attribute(value=Name("os"), attr="path"), attr="join") -> "os.path.join"
        - ast.Subscript(value=Attribute(value=Name("sys"), attr="argv"), slice=1) -> "sys.argv"
        """
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            # Recursively build: value.attr
            value_name = self._get_full_name(node.value)
            return f"{value_name}.{node.attr}" if value_name else node.attr
        elif isinstance(node, ast.Subscript):
            # For subscripts like sys.argv[1], return the base name sys.argv
            return self._get_full_name(node.value)
        elif isinstance(node, ast.Call):
            # For nested calls, get the function being called
            return self._get_full_name(node.func)
        else:
            return None
    
    def _next_id(self) -> str:
        node_id = f"node_{self.node_counter}"
        self.node_counter += 1
        return node_id
