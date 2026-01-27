"""
Code Property Graph (CPG) Parser using Tree-sitter
Similar to Joern/CodeQL for JavaScript and TypeScript

This module provides:
- Complete AST extraction with Tree-sitter
- Lexical scope tracking (functions, blocks, closures)
- Symbol table construction
- Reference resolution
- CPG-compatible output for DFG/CFG construction
- Error-tolerant parsing

Author: Vulcan Static Analysis Engine
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Tuple, Any
from pathlib import Path
from enum import Enum
import logging

try:
    from tree_sitter import Language, Parser, Node as TSNode
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    logging.warning("tree-sitter not installed")

from app.schemas.graph import GraphNode, GraphEdge, SemanticGraph, NodeMetadata
from app.enums.node_type import NodeType
from app.enums.edge_type import EdgeType

logger = logging.getLogger(__name__)


class LanguageType(Enum):
    """Supported languages for CPG extraction"""
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    PYTHON = "python"


@dataclass
class ScopeInfo:
    """Scope information for lexical scoping"""
    scope_id: str
    scope_type: str  # "global", "function", "block", "class"
    parent_scope_id: Optional[str]
    symbols: Dict[str, str]  # symbol_name -> node_id
    start_line: int
    end_line: int


@dataclass
class SymbolReference:
    """Symbol reference for data flow tracking"""
    symbol_name: str
    node_id: str
    scope_id: str
    is_declaration: bool
    is_write: bool
    is_read: bool


class CPGParser:
    """
    Code Property Graph Parser
    
    Extracts a complete CPG from JavaScript/TypeScript code:
    - AST nodes with full parent/child relationships
    - Lexical scopes and symbol tables
    - Symbol references (declarations and uses)
    - Function/class/import extraction
    - Member expression chains (obj.prop.method)
    - Call expression tracking
    
    Output is compatible with DFG/CFG construction pipelines.
    """
    
    def __init__(self, grammar_path: Optional[Path] = None):
        """Initialize CPG parser with Tree-sitter grammars"""
        if not TREE_SITTER_AVAILABLE:
            raise RuntimeError("tree-sitter is required. Install: pip install tree-sitter==0.21.3")
        
        self.grammar_path = grammar_path or self._find_grammar_path()
        self.languages: Dict[LanguageType, Language] = {}
        self.parsers: Dict[LanguageType, Parser] = {}
        
        # Load grammars
        self._load_languages()
        
        # CPG state
        self.node_counter = 0
        self.scopes: Dict[str, ScopeInfo] = {}
        self.current_scope_id: Optional[str] = None
        self.symbol_references: List[SymbolReference] = []
        self.symbol_table: Dict[str, List[str]] = {}  # symbol -> [node_ids]
    
    def _find_grammar_path(self) -> Path:
        """Find grammar files directory"""
        candidates = [
            Path.cwd() / "build",
            Path.cwd() / "tree-sitter-grammars",
            Path.home() / ".tree-sitter",
        ]
        
        for path in candidates:
            if path.exists() and path.is_dir():
                return path
        
        default_path = Path.cwd() / "build"
        default_path.mkdir(exist_ok=True)
        return default_path
    
    def _load_languages(self):
        """Load JavaScript and TypeScript grammars"""
        for lang in [LanguageType.JAVASCRIPT, LanguageType.TYPESCRIPT]:
            try:
                so_file = self.grammar_path / f"{lang.value}.so"
                dll_file = self.grammar_path / f"{lang.value}.dll"
                
                # Check for .so or .dll (Windows)
                grammar_file = so_file if so_file.exists() else dll_file if dll_file.exists() else None
                
                if not grammar_file:
                    logger.warning(f"Grammar not found: {so_file} or {dll_file}")
                    continue
                
                language = Language(str(grammar_file), lang.value)
                self.languages[lang] = language
                
                parser = Parser()
                parser.set_language(language)
                self.parsers[lang] = parser
                
                logger.info(f"Loaded {lang.value} grammar")
            except Exception as e:
                logger.error(f"Failed to load {lang.value}: {e}")
    
    def parse_file(self, filepath: str) -> SemanticGraph:
        """
        Parse a JavaScript or TypeScript file into a CPG.
        
        Args:
            filepath: Path to .js or .ts file
            
        Returns:
            SemanticGraph with full CPG representation
        """
        # Detect language
        ext = Path(filepath).suffix.lower()
        lang = LanguageType.TYPESCRIPT if ext in ['.ts', '.tsx'] else LanguageType.JAVASCRIPT
        
        # Read source code
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                source_code = f.read()
        except Exception as e:
            logger.error(f"Failed to read {filepath}: {e}")
            return SemanticGraph(nodes=[], edges=[])
        
        return self.parse_code(source_code, lang, filepath)
    
    def parse_code(self, source_code: str, language: LanguageType, filename: str = "unknown") -> SemanticGraph:
        """
        Parse source code into a Code Property Graph.
        
        Args:
            source_code: JavaScript/TypeScript source code
            language: Language type
            filename: Filename for reference
            
        Returns:
            SemanticGraph with:
            - AST nodes (functions, classes, expressions)
            - Scope information
            - Symbol references
            - Parent/child relationships
        """
        if language not in self.parsers:
            logger.error(f"No parser for {language.value}")
            return SemanticGraph(nodes=[], edges=[])
        
        # Reset state
        self.node_counter = 0
        self.scopes = {}
        self.current_scope_id = None
        self.symbol_references = []
        self.symbol_table = {}
        
        try:
            # Parse with Tree-sitter
            parser = self.parsers[language]
            tree = parser.parse(bytes(source_code, "utf8"))
            
            # Check for errors (but continue anyway - error-tolerant)
            if tree.root_node.has_error:
                logger.warning(f"Syntax errors in {filename}, continuing with partial parse")
            
            # Create CPG
            nodes: List[GraphNode] = []
            edges: List[GraphEdge] = []
            
            # Create file root node
            file_node_id = self._next_id()
            file_node = GraphNode(
                id=file_node_id,
                type=NodeType.FILE,
                name=filename,
                file=filename,
                line=1,
                column=0,
                metadata=NodeMetadata(
                    language=language.value,
                    scope_id="global"
                )
            )
            nodes.append(file_node)
            
            # Create global scope
            global_scope = ScopeInfo(
                scope_id="global",
                scope_type="global",
                parent_scope_id=None,
                symbols={},
                start_line=1,
                end_line=tree.root_node.end_point[0] + 1
            )
            self.scopes["global"] = global_scope
            self.current_scope_id = "global"
            
            # Extract CPG from AST
            self._extract_cpg(tree.root_node, file_node_id, source_code, filename, nodes, edges, language)
            
            # Build symbol table
            for ref in self.symbol_references:
                if ref.symbol_name not in self.symbol_table:
                    self.symbol_table[ref.symbol_name] = []
                self.symbol_table[ref.symbol_name].append(ref.node_id)
            
            # Create semantic graph
            graph = SemanticGraph(
                nodes=nodes,
                edges=edges,
                symbol_table=self.symbol_table,
                scopes={sid: {
                    "type": scope.scope_type,
                    "parent": scope.parent_scope_id,
                    "symbols": scope.symbols,
                    "range": (scope.start_line, scope.end_line)
                } for sid, scope in self.scopes.items()}
            )
            
            logger.info(f"Extracted CPG: {len(nodes)} nodes, {len(edges)} edges, {len(self.scopes)} scopes")
            
            return graph
            
        except Exception as e:
            logger.error(f"Failed to parse {filename}: {e}")
            import traceback
            traceback.print_exc()
            return SemanticGraph(nodes=[], edges=[])
    
    def _extract_cpg(
        self,
        ts_node: TSNode,
        parent_id: str,
        source_code: str,
        filename: str,
        nodes: List[GraphNode],
        edges: List[GraphEdge],
        language: LanguageType
    ):
        """
        Recursively extract CPG nodes from Tree-sitter AST.
        
        This is the core method that:
        - Identifies important constructs (functions, classes, etc.)
        - Creates scope boundaries
        - Tracks symbol declarations and references
        - Builds parent/child relationships
        """
        node_type = ts_node.type
        
        # Skip certain node types
        if self._should_skip(node_type):
            for child in ts_node.children:
                self._extract_cpg(child, parent_id, source_code, filename, nodes, edges, language)
            return
        
        # Extract source code for this node
        start_byte = ts_node.start_byte
        end_byte = ts_node.end_byte
        node_source = source_code[start_byte:end_byte]
        
        # Truncate long source code
        if len(node_source) > 200:
            node_source = node_source[:200] + "..."
        
        # Create node based on type
        node_id = self._next_id()
        graph_node = None
        
        # FUNCTION DECLARATIONS
        if node_type in ("function_declaration", "function"):
            graph_node = self._extract_function(ts_node, node_id, source_code, filename, language)
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
                
                # Create function scope
                self._enter_scope(node_id, "function", ts_node, graph_node.name)
                
                # Process children
                for child in ts_node.children:
                    self._extract_cpg(child, node_id, source_code, filename, nodes, edges, language)
                
                self._exit_scope()
                return
        
        # ARROW FUNCTIONS
        elif node_type == "arrow_function":
            graph_node = self._extract_arrow_function(ts_node, node_id, source_code, filename, language)
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
                
                # Create function scope
                self._enter_scope(node_id, "function", ts_node, graph_node.name or "anonymous")
                
                for child in ts_node.children:
                    self._extract_cpg(child, node_id, source_code, filename, nodes, edges, language)
                
                self._exit_scope()
                return
        
        # CLASS DECLARATIONS
        elif node_type == "class_declaration":
            graph_node = self._extract_class(ts_node, node_id, source_code, filename, language)
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
                
                # Create class scope
                self._enter_scope(node_id, "class", ts_node, graph_node.name)
                
                for child in ts_node.children:
                    self._extract_cpg(child, node_id, source_code, filename, nodes, edges, language)
                
                self._exit_scope()
                return
        
        # METHOD DEFINITIONS
        elif node_type == "method_definition":
            graph_node = self._extract_method(ts_node, node_id, source_code, filename, language)
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
                
                self._enter_scope(node_id, "function", ts_node, graph_node.name)
                
                for child in ts_node.children:
                    self._extract_cpg(child, node_id, source_code, filename, nodes, edges, language)
                
                self._exit_scope()
                return
        
        # IMPORTS
        elif node_type in ("import_statement", "import_specifier"):
            graph_node = self._extract_import(ts_node, node_id, source_code, filename, language)
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        
        # EXPORTS
        elif node_type in ("export_statement", "export_specifier"):
            graph_node = self._extract_export(ts_node, node_id, source_code, filename, language)
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        
        # CALL EXPRESSIONS
        elif node_type == "call_expression":
            graph_node = self._extract_call(ts_node, node_id, source_code, filename, language)
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        
        # MEMBER EXPRESSIONS (obj.prop.method)
        elif node_type == "member_expression":
            graph_node = self._extract_member_expression(ts_node, node_id, source_code, filename, language)
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        
        # VARIABLE DECLARATIONS
        elif node_type == "variable_declaration":
            graph_node = self._extract_variable_declaration(ts_node, node_id, source_code, filename, language)
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        
        # IDENTIFIERS (symbol references)
        elif node_type == "identifier":
            graph_node = self._extract_identifier(ts_node, node_id, source_code, filename, language)
            if graph_node:
                nodes.append(graph_node)
                edges.append(GraphEdge(from_node=parent_id, to_node=node_id, type=EdgeType.AST_CHILD))
        
        # BLOCK STATEMENTS (create scope)
        elif node_type == "statement_block":
            self._enter_scope(self._next_id(), "block", ts_node, "block")
            
            for child in ts_node.children:
                self._extract_cpg(child, parent_id, source_code, filename, nodes, edges, language)
            
            self._exit_scope()
            return
        
        # Process remaining children
        for child in ts_node.children:
            self._extract_cpg(child, parent_id if not graph_node else node_id, source_code, filename, nodes, edges, language)
    
    def _extract_function(self, ts_node: TSNode, node_id: str, source_code: str, filename: str, language: LanguageType) -> Optional[GraphNode]:
        """Extract function declaration"""
        name = self._find_child_text(ts_node, "identifier", source_code)
        
        # Check for async
        is_async = any(child.type == "async" for child in ts_node.children)
        
        # Check for generator
        is_generator = any(child.type == "*" for child in ts_node.children)
        
        metadata = NodeMetadata(
            language=language.value,
            scope_id=self.current_scope_id,
            symbol_name=name,
            is_async=is_async,
            is_generator=is_generator
        )
        
        # Register symbol
        if name:
            self._register_symbol(name, node_id, is_declaration=True)
        
        return GraphNode(
            id=node_id,
            type=NodeType.ASYNC_FUNCTION if is_async else NodeType.FUNCTION,
            name=name or "anonymous",
            file=filename,
            line=ts_node.start_point[0] + 1,
            column=ts_node.start_point[1],
            source_code=source_code[ts_node.start_byte:ts_node.end_byte][:200],
            metadata=metadata
        )
    
    def _extract_arrow_function(self, ts_node: TSNode, node_id: str, source_code: str, filename: str, language: LanguageType) -> Optional[GraphNode]:
        """Extract arrow function"""
        # Arrow functions might not have names (anonymous)
        # Try to find parent variable declarator for name
        name = "anonymous"
        
        is_async = "async" in source_code[ts_node.start_byte:ts_node.start_byte+10]
        
        metadata = NodeMetadata(
            language=language.value,
            scope_id=self.current_scope_id,
            is_async=is_async
        )
        
        return GraphNode(
            id=node_id,
            type=NodeType.ARROW_FUNCTION,
            name=name,
            file=filename,
            line=ts_node.start_point[0] + 1,
            column=ts_node.start_point[1],
            source_code=source_code[ts_node.start_byte:ts_node.end_byte][:200],
            metadata=metadata
        )
    
    def _extract_class(self, ts_node: TSNode, node_id: str, source_code: str, filename: str, language: LanguageType) -> Optional[GraphNode]:
        """Extract class declaration"""
        name = self._find_child_text(ts_node, "identifier", source_code) or "AnonymousClass"
        
        metadata = NodeMetadata(
            language=language.value,
            scope_id=self.current_scope_id,
            symbol_name=name
        )
        
        if name:
            self._register_symbol(name, node_id, is_declaration=True)
        
        return GraphNode(
            id=node_id,
            type=NodeType.CLASS,
            name=name,
            file=filename,
            line=ts_node.start_point[0] + 1,
            column=ts_node.start_point[1],
            source_code=source_code[ts_node.start_byte:ts_node.end_byte][:200],
            metadata=metadata
        )
    
    def _extract_method(self, ts_node: TSNode, node_id: str, source_code: str, filename: str, language: LanguageType) -> Optional[GraphNode]:
        """Extract method definition"""
        name = self._find_child_text(ts_node, "property_identifier", source_code)
        
        is_async = any(child.type == "async" for child in ts_node.children)
        is_generator = any(child.type == "*" for child in ts_node.children)
        
        # Check visibility (TypeScript)
        visibility = None
        for child in ts_node.children:
            if child.type in ("public", "private", "protected"):
                visibility = child.type
                break
        
        metadata = NodeMetadata(
            language=language.value,
            scope_id=self.current_scope_id,
            symbol_name=name,
            is_async=is_async,
            is_generator=is_generator,
            visibility=visibility
        )
        
        return GraphNode(
            id=node_id,
            type=NodeType.FUNCTION,
            name=name or "method",
            file=filename,
            line=ts_node.start_point[0] + 1,
            column=ts_node.start_point[1],
            source_code=source_code[ts_node.start_byte:ts_node.end_byte][:200],
            metadata=metadata
        )
    
    def _extract_import(self, ts_node: TSNode, node_id: str, source_code: str, filename: str, language: LanguageType) -> Optional[GraphNode]:
        """Extract import statement"""
        import_text = source_code[ts_node.start_byte:ts_node.end_byte]
        
        # Extract imported names
        imported_names = []
        for child in ts_node.children:
            if child.type in ("identifier", "import_clause"):
                name = source_code[child.start_byte:child.end_byte]
                imported_names.append(name)
        
        metadata = NodeMetadata(
            language=language.value,
            scope_id=self.current_scope_id
        )
        
        return GraphNode(
            id=node_id,
            type=NodeType.IMPORT,
            name=", ".join(imported_names) if imported_names else "import",
            value=import_text[:100],
            file=filename,
            line=ts_node.start_point[0] + 1,
            column=ts_node.start_point[1],
            source_code=import_text,
            metadata=metadata
        )
    
    def _extract_export(self, ts_node: TSNode, node_id: str, source_code: str, filename: str, language: LanguageType) -> Optional[GraphNode]:
        """Extract export statement"""
        export_text = source_code[ts_node.start_byte:ts_node.end_byte]
        
        metadata = NodeMetadata(
            language=language.value,
            scope_id=self.current_scope_id,
            is_exported=True
        )
        
        return GraphNode(
            id=node_id,
            type=NodeType.EXPRESSION,
            name="export",
            value=export_text[:100],
            file=filename,
            line=ts_node.start_point[0] + 1,
            column=ts_node.start_point[1],
            source_code=export_text,
            metadata=metadata
        )
    
    def _extract_call(self, ts_node: TSNode, node_id: str, source_code: str, filename: str, language: LanguageType) -> Optional[GraphNode]:
        """Extract call expression"""
        call_text = source_code[ts_node.start_byte:ts_node.end_byte]
        
        # Extract function name
        func_name = None
        for child in ts_node.children:
            if child.type in ("identifier", "member_expression"):
                func_name = source_code[child.start_byte:child.end_byte]
                break
        
        metadata = NodeMetadata(
            language=language.value,
            scope_id=self.current_scope_id
        )
        
        return GraphNode(
            id=node_id,
            type=NodeType.CALL_EXPRESSION,
            name=func_name or "call",
            value=call_text[:100],
            file=filename,
            line=ts_node.start_point[0] + 1,
            column=ts_node.start_point[1],
            source_code=call_text,
            metadata=metadata
        )
    
    def _extract_member_expression(self, ts_node: TSNode, node_id: str, source_code: str, filename: str, language: LanguageType) -> Optional[GraphNode]:
        """Extract member expression (obj.prop.method)"""
        member_text = source_code[ts_node.start_byte:ts_node.end_byte]
        
        metadata = NodeMetadata(
            language=language.value,
            scope_id=self.current_scope_id
        )
        
        return GraphNode(
            id=node_id,
            type=NodeType.MEMBER_ACCESS,
            name=member_text[:50],
            value=member_text,
            file=filename,
            line=ts_node.start_point[0] + 1,
            column=ts_node.start_point[1],
            source_code=member_text,
            metadata=metadata
        )
    
    def _extract_variable_declaration(self, ts_node: TSNode, node_id: str, source_code: str, filename: str, language: LanguageType) -> Optional[GraphNode]:
        """Extract variable declaration"""
        var_text = source_code[ts_node.start_byte:ts_node.end_byte]
        
        # Extract variable names
        var_names = []
        for child in ts_node.children:
            if child.type == "variable_declarator":
                for subchild in child.children:
                    if subchild.type == "identifier":
                        name = source_code[subchild.start_byte:subchild.end_byte]
                        var_names.append(name)
                        self._register_symbol(name, node_id, is_declaration=True)
        
        metadata = NodeMetadata(
            language=language.value,
            scope_id=self.current_scope_id
        )
        
        return GraphNode(
            id=node_id,
            type=NodeType.ASSIGNMENT,
            name=", ".join(var_names) if var_names else "var",
            value=var_text[:100],
            file=filename,
            line=ts_node.start_point[0] + 1,
            column=ts_node.start_point[1],
            source_code=var_text,
            metadata=metadata
        )
    
    def _extract_identifier(self, ts_node: TSNode, node_id: str, source_code: str, filename: str, language: LanguageType) -> Optional[GraphNode]:
        """Extract identifier (symbol reference)"""
        name = source_code[ts_node.start_byte:ts_node.end_byte]
        
        # Register as symbol reference (use)
        self._register_symbol(name, node_id, is_declaration=False, is_read=True)
        
        metadata = NodeMetadata(
            language=language.value,
            scope_id=self.current_scope_id,
            symbol_name=name
        )
        
        return GraphNode(
            id=node_id,
            type=NodeType.IDENTIFIER,
            name=name,
            file=filename,
            line=ts_node.start_point[0] + 1,
            column=ts_node.start_point[1],
            source_code=name,
            metadata=metadata
        )
    
    # Helper methods
    
    def _should_skip(self, node_type: str) -> bool:
        """Check if node type should be skipped"""
        skip_types = {
            "program", "source_file",  # Root nodes
            "(", ")", "{", "}", "[", "]", ",", ";", ":",  # Punctuation
            "comment", "//", "/*", "*/",  # Comments
        }
        return node_type in skip_types
    
    def _find_child_text(self, ts_node: TSNode, child_type: str, source_code: str) -> Optional[str]:
        """Find text of first child with given type"""
        for child in ts_node.children:
            if child.type == child_type:
                return source_code[child.start_byte:child.end_byte]
        return None
    
    def _enter_scope(self, scope_id: str, scope_type: str, ts_node: TSNode, name: str):
        """Enter a new lexical scope"""
        scope = ScopeInfo(
            scope_id=scope_id,
            scope_type=scope_type,
            parent_scope_id=self.current_scope_id,
            symbols={},
            start_line=ts_node.start_point[0] + 1,
            end_line=ts_node.end_point[0] + 1
        )
        self.scopes[scope_id] = scope
        self.current_scope_id = scope_id
        logger.debug(f"Entered {scope_type} scope '{name}' ({scope_id})")
    
    def _exit_scope(self):
        """Exit current scope"""
        if self.current_scope_id and self.current_scope_id in self.scopes:
            parent_id = self.scopes[self.current_scope_id].parent_scope_id
            logger.debug(f"Exiting scope {self.current_scope_id}")
            self.current_scope_id = parent_id
    
    def _register_symbol(self, symbol_name: str, node_id: str, is_declaration: bool = False, is_write: bool = False, is_read: bool = False):
        """Register a symbol reference"""
        if not symbol_name:
            return
        
        # Add to current scope if declaration
        if is_declaration and self.current_scope_id:
            if self.current_scope_id in self.scopes:
                self.scopes[self.current_scope_id].symbols[symbol_name] = node_id
        
        # Track reference
        ref = SymbolReference(
            symbol_name=symbol_name,
            node_id=node_id,
            scope_id=self.current_scope_id or "global",
            is_declaration=is_declaration,
            is_write=is_write,
            is_read=is_read
        )
        self.symbol_references.append(ref)
    
    def _next_id(self) -> str:
        """Generate unique node ID"""
        node_id = f"node_{self.node_counter}"
        self.node_counter += 1
        return node_id


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Example JavaScript code
    js_code = """
import { fetch } from 'node-fetch';

async function getUserData(userId) {
    const user = await fetch(`/api/users/${userId}`);
    return user.json();
}

class UserService {
    constructor(apiUrl) {
        this.apiUrl = apiUrl;
    }
    
    async authenticate(username, password) {
        const response = await fetch(this.apiUrl + '/auth', {
            method: 'POST',
            body: JSON.stringify({ username, password })
        });
        return response.json();
    }
}

export { getUserData, UserService };
"""
    
    parser = CPGParser()
    graph = parser.parse_code(js_code, LanguageType.JAVASCRIPT, "example.js")
    
    print(f"\nCPG Extraction Results:")
    print(f"Nodes: {len(graph.nodes)}")
    print(f"Edges: {len(graph.edges)}")
    print(f"Scopes: {len(graph.scopes)}")
    print(f"Symbols: {len(graph.symbol_table)}")
    
    print(f"\nFunction nodes:")
    for node in graph.nodes:
        if node.type in (NodeType.FUNCTION, NodeType.ASYNC_FUNCTION, NodeType.ARROW_FUNCTION):
            print(f"  - {node.name} (line {node.line}, scope: {node.metadata.scope_id if node.metadata else 'N/A'})")
    
    print(f"\nSymbol table:")
    for symbol, node_ids in graph.symbol_table.items():
        print(f"  {symbol}: {len(node_ids)} references")
