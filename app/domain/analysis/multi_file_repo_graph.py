"""
Multi-File Repository Graph Linking
====================================

Extends CPG engine to support multi-file and multi-module analysis.

Features:
- Global symbol table for entire repository
- Import/export resolution (Python and JavaScript)
- Cross-file graph edges (IMPORT_CALL, EXPORT_RET, MODULE_REF)
- Inter-file data flow path traversal
- Name-based resolution (no full type inference required)
- Scalable to large repositories

Architecture:
1. RepositoryScanner - Discovers all source files
2. GlobalSymbolTable - Tracks exports/imports across files
3. ImportExportResolver - Resolves module references
4. CrossFileLinker - Creates inter-file edges
5. MultiFileDFG - Extends interprocedural DFG across files
"""

from typing import Dict, List, Set, Optional, Tuple, Any
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
import re
from collections import defaultdict

from app.schemas.graph import GraphNode, GraphEdge, SemanticGraph
from app.enums.edge_type import EdgeType
from app.domain.analysis.cpg_parser import CPGParser
from app.domain.analysis.interprocedural_dfg import InterproceduralDFG
from pydantic import BaseModel


class CrossFileEdgeType(str, Enum):
    """Edge types for cross-file relationships"""
    IMPORT_CALL = "IMPORT_CALL"       # Import statement → Exported symbol
    EXPORT_RET = "EXPORT_RET"         # Exported symbol → Import usage
    MODULE_REF = "MODULE_REF"         # Module reference edge
    FILE_CONTAINS = "FILE_CONTAINS"   # File → Node (containment)


class ImportType(str, Enum):
    """Types of import statements"""
    # Python
    PYTHON_IMPORT = "import"           # import module
    PYTHON_FROM = "from"               # from module import name
    PYTHON_IMPORT_AS = "import_as"     # import module as alias
    
    # JavaScript
    JS_ES6_IMPORT = "es6_import"       # import { x } from 'module'
    JS_ES6_DEFAULT = "es6_default"     # import x from 'module'
    JS_REQUIRE = "require"             # const x = require('module')
    JS_DYNAMIC = "dynamic_import"      # import('module')


@dataclass
class ExportedSymbol:
    """Represents an exported symbol from a module"""
    name: str
    node_id: str
    file_path: str
    export_type: str                   # "function", "class", "variable", "default"
    is_default: bool = False
    alias: Optional[str] = None


@dataclass
class ImportedSymbol:
    """Represents an imported symbol"""
    name: str
    node_id: str
    file_path: str
    source_module: str                 # Module path or name
    import_type: ImportType
    alias: Optional[str] = None
    is_wildcard: bool = False          # For import *


@dataclass
class ModuleDefinition:
    """Represents a module/file in the repository"""
    file_path: str
    module_name: str                   # Computed module name
    language: str                      # "python" or "javascript"
    exports: List[ExportedSymbol] = field(default_factory=list)
    imports: List[ImportedSymbol] = field(default_factory=list)
    cpg: Optional[SemanticGraph] = None


class GlobalSymbolTable:
    """
    Global symbol table for entire repository
    
    Tracks:
    - All exported symbols from each module
    - All imported symbols in each module
    - Module-to-file mappings
    - Symbol-to-location mappings
    """
    
    def __init__(self):
        # Module name → ModuleDefinition
        self.modules: Dict[str, ModuleDefinition] = {}
        
        # Symbol name → List[ExportedSymbol] (can have duplicates across files)
        self.exported_symbols: Dict[str, List[ExportedSymbol]] = defaultdict(list)
        
        # File path → ModuleDefinition
        self.file_to_module: Dict[str, ModuleDefinition] = {}
        
        # Import resolution cache: (file, module_name) → resolved_file
        self.import_cache: Dict[Tuple[str, str], Optional[str]] = {}
    
    def add_module(self, module: ModuleDefinition):
        """Register a module in the global symbol table"""
        self.modules[module.module_name] = module
        self.file_to_module[module.file_path] = module
        
        # Index exports
        for export in module.exports:
            self.exported_symbols[export.name].append(export)
    
    def find_export(
        self,
        symbol_name: str,
        from_file: Optional[str] = None
    ) -> List[ExportedSymbol]:
        """
        Find exported symbols by name
        
        Args:
            symbol_name: Name to search for
            from_file: Optional file path to prioritize local exports
        
        Returns:
            List of matching exported symbols
        """
        matches = self.exported_symbols.get(symbol_name, [])
        
        if from_file and matches:
            # Prioritize exports from the same file (for relative imports)
            same_file = [e for e in matches if e.file_path == from_file]
            if same_file:
                return same_file
        
        return matches
    
    def resolve_import(
        self,
        importing_file: str,
        module_path: str,
        symbol_name: Optional[str] = None
    ) -> Optional[str]:
        """
        Resolve an import to a file path
        
        Args:
            importing_file: File doing the import
            module_path: Module being imported (e.g., "./utils", "requests")
            symbol_name: Specific symbol being imported
        
        Returns:
            Resolved file path or None if not found
        """
        cache_key = (importing_file, module_path)
        if cache_key in self.import_cache:
            return self.import_cache[cache_key]
        
        resolved = self._resolve_import_internal(importing_file, module_path)
        self.import_cache[cache_key] = resolved
        return resolved
    
    def _resolve_import_internal(
        self,
        importing_file: str,
        module_path: str
    ) -> Optional[str]:
        """Internal import resolution logic"""
        # Relative import (./file, ../file)
        if module_path.startswith('.'):
            base_dir = Path(importing_file).parent
            resolved = self._resolve_relative_import(base_dir, module_path)
            if resolved:
                return str(resolved)
        
        # Absolute module name
        # Try exact match first
        if module_path in self.modules:
            return self.modules[module_path].file_path
        
        # Try converting module path to file path
        # Python: package.module → package/module.py
        # JavaScript: 'utils/helper' → utils/helper.js
        for module_def in self.modules.values():
            if self._module_matches(module_def.module_name, module_path):
                return module_def.file_path
        
        return None
    
    def _resolve_relative_import(
        self,
        base_dir: Path,
        relative_path: str
    ) -> Optional[Path]:
        """Resolve relative import path"""
        # Remove leading dots and convert to path
        path_parts = relative_path.lstrip('.').lstrip('/').split('/')
        
        # Count leading dots for parent directory traversal
        parent_levels = len(relative_path) - len(relative_path.lstrip('.'))
        
        current = base_dir
        for _ in range(parent_levels - 1):
            current = current.parent
        
        target = current / '/'.join(path_parts)
        
        # Try with extensions
        for ext in ['.py', '.js', '.ts', '/index.js', '/index.py', '']:
            candidate = Path(str(target) + ext)
            if str(candidate) in self.file_to_module:
                return candidate
        
        return None
    
    def _module_matches(self, module_name: str, import_path: str) -> bool:
        """Check if module name matches import path"""
        # Convert both to normalized form
        normalized_module = module_name.replace('.', '/').replace('\\', '/')
        normalized_import = import_path.replace('.', '/').replace('\\', '/')
        
        return normalized_module.endswith(normalized_import) or \
               normalized_import.endswith(normalized_module)


class RepositoryScanner:
    """
    Scans repository to discover all source files
    
    Supports:
    - Python (.py)
    - JavaScript (.js, .jsx)
    - TypeScript (.ts, .tsx)
    """
    
    def __init__(self, repo_path: str, exclude_patterns: Optional[List[str]] = None):
        self.repo_path = Path(repo_path)
        self.exclude_patterns = exclude_patterns or [
            'node_modules',
            'venv',
            '__pycache__',
            '.git',
            'dist',
            'build',
            '*.pyc',
            '*.min.js'
        ]
    
    def scan(self) -> List[Path]:
        """
        Scan repository and return list of source files
        
        Returns:
            List of Path objects for source files
        """
        source_files = []
        
        # Supported extensions
        extensions = {'.py', '.js', '.jsx', '.ts', '.tsx'}
        
        for file_path in self.repo_path.rglob('*'):
            if not file_path.is_file():
                continue
            
            if file_path.suffix not in extensions:
                continue
            
            # Check exclusion patterns
            if self._should_exclude(file_path):
                continue
            
            source_files.append(file_path)
        
        return sorted(source_files)
    
    def _should_exclude(self, file_path: Path) -> bool:
        """Check if file should be excluded"""
        file_str = str(file_path)
        
        for pattern in self.exclude_patterns:
            if '*' in pattern:
                # Glob pattern
                if file_path.match(pattern):
                    return True
            else:
                # Simple substring match
                if pattern in file_str:
                    return True
        
        return False


class ImportExportResolver:
    """
    Resolves imports and exports for Python and JavaScript
    
    Extracts:
    - Python: import, from...import, __all__
    - JavaScript: import, export, require, module.exports
    """
    
    def __init__(self, cpg: SemanticGraph, file_path: str, language: str):
        self.cpg = cpg
        self.file_path = file_path
        self.language = language.lower()
    
    def extract_exports(self) -> List[ExportedSymbol]:
        """Extract all exported symbols from CPG"""
        if self.language == "python":
            return self._extract_python_exports()
        elif self.language in ("javascript", "typescript"):
            return self._extract_javascript_exports()
        return []
    
    def extract_imports(self) -> List[ImportedSymbol]:
        """Extract all imported symbols from CPG"""
        if self.language == "python":
            return self._extract_python_imports()
        elif self.language in ("javascript", "typescript"):
            return self._extract_javascript_imports()
        return []
    
    # ======================
    # Python Export/Import
    # ======================
    
    def _extract_python_exports(self) -> List[ExportedSymbol]:
        """
        Extract Python exports
        
        In Python, exports are:
        1. Top-level function definitions
        2. Top-level class definitions
        3. Top-level variable assignments
        4. Symbols listed in __all__
        """
        exports = []
        
        # Find top-level definitions
        for node in self.cpg.nodes:
            # Top-level = no parent function or class
            if self._is_top_level(node.id):
                if node.node_type in ["FUNCTION", "ASYNC_FUNCTION"]:
                    exports.append(ExportedSymbol(
                        name=node.name,
                        node_id=node.id,
                        file_path=self.file_path,
                        export_type="function"
                    ))
                elif node.node_type == "CLASS":
                    exports.append(ExportedSymbol(
                        name=node.name,
                        node_id=node.id,
                        file_path=self.file_path,
                        export_type="class"
                    ))
                elif node.node_type == "VARIABLE_DECLARATION":
                    exports.append(ExportedSymbol(
                        name=node.name,
                        node_id=node.id,
                        file_path=self.file_path,
                        export_type="variable"
                    ))
        
        # Check for __all__ definition (explicit exports)
        all_exports = self._find_python_all_exports()
        if all_exports:
            # Filter exports to only those in __all__
            exports = [e for e in exports if e.name in all_exports]
        
        return exports
    
    def _extract_python_imports(self) -> List[ImportedSymbol]:
        """
        Extract Python imports
        
        Patterns:
        1. import module
        2. import module as alias
        3. from module import name
        4. from module import name as alias
        5. from module import *
        """
        imports = []
        
        for node in self.cpg.nodes:
            if node.node_type == "IMPORT":
                code = node.code or ""
                
                if code.startswith("from "):
                    # from module import ...
                    imports.extend(self._parse_python_from_import(node))
                elif code.startswith("import "):
                    # import module
                    imports.extend(self._parse_python_import(node))
        
        return imports
    
    def _parse_python_from_import(self, node: GraphNode) -> List[ImportedSymbol]:
        """Parse 'from module import name' statements"""
        code = node.code or ""
        imports = []
        
        # Pattern: from <module> import <names>
        match = re.match(r'from\s+([\w.]+)\s+import\s+(.+)', code)
        if match:
            module = match.group(1)
            imports_str = match.group(2)
            
            # Handle wildcard
            if imports_str.strip() == '*':
                imports.append(ImportedSymbol(
                    name="*",
                    node_id=node.id,
                    file_path=self.file_path,
                    source_module=module,
                    import_type=ImportType.PYTHON_FROM,
                    is_wildcard=True
                ))
            else:
                # Parse individual imports
                for item in imports_str.split(','):
                    item = item.strip()
                    
                    # Handle 'as' alias
                    if ' as ' in item:
                        name, alias = item.split(' as ')
                        name = name.strip()
                        alias = alias.strip()
                    else:
                        name = item
                        alias = None
                    
                    imports.append(ImportedSymbol(
                        name=name,
                        node_id=node.id,
                        file_path=self.file_path,
                        source_module=module,
                        import_type=ImportType.PYTHON_FROM,
                        alias=alias
                    ))
        
        return imports
    
    def _parse_python_import(self, node: GraphNode) -> List[ImportedSymbol]:
        """Parse 'import module' statements"""
        code = node.code or ""
        imports = []
        
        # Pattern: import <module> [as <alias>]
        code = code.replace("import ", "").strip()
        
        for item in code.split(','):
            item = item.strip()
            
            if ' as ' in item:
                module, alias = item.split(' as ')
                module = module.strip()
                alias = alias.strip()
            else:
                module = item
                alias = None
            
            imports.append(ImportedSymbol(
                name=module,
                node_id=node.id,
                file_path=self.file_path,
                source_module=module,
                import_type=ImportType.PYTHON_IMPORT,
                alias=alias
            ))
        
        return imports
    
    def _find_python_all_exports(self) -> Optional[Set[str]]:
        """Find symbols listed in __all__"""
        for node in self.cpg.nodes:
            if node.name == "__all__" and node.node_type == "VARIABLE_DECLARATION":
                # Parse __all__ = ['name1', 'name2', ...]
                code = node.code or ""
                match = re.search(r'__all__\s*=\s*\[(.*?)\]', code)
                if match:
                    items_str = match.group(1)
                    items = [
                        item.strip().strip("'\"")
                        for item in items_str.split(',')
                        if item.strip()
                    ]
                    return set(items)
        return None
    
    # ======================
    # JavaScript Export/Import
    # ======================
    
    def _extract_javascript_exports(self) -> List[ExportedSymbol]:
        """
        Extract JavaScript exports
        
        Patterns:
        1. export function name() {}
        2. export class Name {}
        3. export const name = ...
        4. export { name1, name2 }
        5. export default ...
        6. module.exports = ...
        """
        exports = []
        
        for node in self.cpg.nodes:
            code = (node.code or "").strip()
            
            # export default
            if "export default" in code:
                # Find the exported symbol
                exported_name = self._extract_default_export_name(node)
                exports.append(ExportedSymbol(
                    name=exported_name or "default",
                    node_id=node.id,
                    file_path=self.file_path,
                    export_type="default",
                    is_default=True
                ))
            
            # export function/class/const
            elif code.startswith("export "):
                if node.node_type in ["FUNCTION", "ASYNC_FUNCTION"]:
                    exports.append(ExportedSymbol(
                        name=node.name,
                        node_id=node.id,
                        file_path=self.file_path,
                        export_type="function"
                    ))
                elif node.node_type == "CLASS":
                    exports.append(ExportedSymbol(
                        name=node.name,
                        node_id=node.id,
                        file_path=self.file_path,
                        export_type="class"
                    ))
                elif node.node_type == "VARIABLE_DECLARATION":
                    exports.append(ExportedSymbol(
                        name=node.name,
                        node_id=node.id,
                        file_path=self.file_path,
                        export_type="variable"
                    ))
            
            # module.exports = ...
            elif "module.exports" in code:
                # CommonJS export
                exported_name = node.name or "default"
                exports.append(ExportedSymbol(
                    name=exported_name,
                    node_id=node.id,
                    file_path=self.file_path,
                    export_type="commonjs",
                    is_default=True
                ))
        
        return exports
    
    def _extract_javascript_imports(self) -> List[ImportedSymbol]:
        """
        Extract JavaScript imports
        
        Patterns:
        1. import { name } from 'module'
        2. import name from 'module'
        3. import * as name from 'module'
        4. const name = require('module')
        5. import('module') - dynamic
        """
        imports = []
        
        for node in self.cpg.nodes:
            code = (node.code or "").strip()
            
            if code.startswith("import "):
                imports.extend(self._parse_javascript_es6_import(node))
            elif "require(" in code:
                imports.extend(self._parse_javascript_require(node))
            elif code.startswith("import("):
                # Dynamic import
                module = self._extract_module_path(code)
                if module:
                    imports.append(ImportedSymbol(
                        name=module,
                        node_id=node.id,
                        file_path=self.file_path,
                        source_module=module,
                        import_type=ImportType.JS_DYNAMIC
                    ))
        
        return imports
    
    def _parse_javascript_es6_import(self, node: GraphNode) -> List[ImportedSymbol]:
        """Parse ES6 import statements"""
        code = node.code or ""
        imports = []
        
        # Extract module path
        module = self._extract_module_path(code)
        if not module:
            return []
        
        # import { name1, name2 } from 'module'
        if '{' in code:
            match = re.search(r'\{([^}]+)\}', code)
            if match:
                names_str = match.group(1)
                for item in names_str.split(','):
                    item = item.strip()
                    
                    if ' as ' in item:
                        name, alias = item.split(' as ')
                        name = name.strip()
                        alias = alias.strip()
                    else:
                        name = item
                        alias = None
                    
                    imports.append(ImportedSymbol(
                        name=name,
                        node_id=node.id,
                        file_path=self.file_path,
                        source_module=module,
                        import_type=ImportType.JS_ES6_IMPORT,
                        alias=alias
                    ))
        
        # import * as name from 'module'
        elif '* as ' in code:
            match = re.search(r'\*\s+as\s+(\w+)', code)
            if match:
                alias = match.group(1)
                imports.append(ImportedSymbol(
                    name="*",
                    node_id=node.id,
                    file_path=self.file_path,
                    source_module=module,
                    import_type=ImportType.JS_ES6_IMPORT,
                    alias=alias,
                    is_wildcard=True
                ))
        
        # import name from 'module' (default import)
        else:
            match = re.match(r'import\s+(\w+)\s+from', code)
            if match:
                name = match.group(1)
                imports.append(ImportedSymbol(
                    name="default",
                    node_id=node.id,
                    file_path=self.file_path,
                    source_module=module,
                    import_type=ImportType.JS_ES6_DEFAULT,
                    alias=name
                ))
        
        return imports
    
    def _parse_javascript_require(self, node: GraphNode) -> List[ImportedSymbol]:
        """Parse CommonJS require() statements"""
        code = node.code or ""
        imports = []
        
        # const name = require('module')
        match = re.search(r'require\([\'"]([^\'"]+)[\'"]\)', code)
        if match:
            module = match.group(1)
            
            # Extract variable name
            var_match = re.match(r'(?:const|let|var)\s+(\w+)', code)
            alias = var_match.group(1) if var_match else None
            
            imports.append(ImportedSymbol(
                name="default",
                node_id=node.id,
                file_path=self.file_path,
                source_module=module,
                import_type=ImportType.JS_REQUIRE,
                alias=alias
            ))
        
        return imports
    
    # ======================
    # Helper Methods
    # ======================
    
    def _is_top_level(self, node_id: str) -> bool:
        """Check if node is at top level (not inside function/class)"""
        # Walk up AST_CHILD edges to check if inside function/class
        current = node_id
        visited = set()
        
        while current and current not in visited:
            visited.add(current)
            
            # Find parent
            parent_edge = next(
                (e for e in self.cpg.edges
                 if e.target == current and e.edge_type == "AST_CHILD"),
                None
            )
            
            if not parent_edge:
                return True  # Reached root
            
            parent_node = next(
                (n for n in self.cpg.nodes if n.id == parent_edge.source),
                None
            )
            
            if parent_node and parent_node.node_type in [
                "FUNCTION", "ASYNC_FUNCTION", "CLASS", "METHOD"
            ]:
                return False  # Inside function/class
            
            current = parent_edge.source
        
        return True
    
    def _extract_default_export_name(self, node: GraphNode) -> Optional[str]:
        """Extract name from export default statement"""
        # Could be: export default function name() {}
        #           export default class Name {}
        #           export default name
        if node.name:
            return node.name
        
        code = node.code or ""
        match = re.search(r'export\s+default\s+(\w+)', code)
        return match.group(1) if match else None
    
    def _extract_module_path(self, code: str) -> Optional[str]:
        """Extract module path from import/require statement"""
        # Look for quoted string
        match = re.search(r'[\'"]([^\'"]+)[\'"]', code)
        return match.group(1) if match else None


class CrossFileLinker:
    """
    Creates cross-file graph edges
    
    Edge types:
    - IMPORT_CALL: Import statement → Exported symbol
    - EXPORT_RET: Exported symbol → Import usage
    - MODULE_REF: Module reference edge
    """
    
    def __init__(self, global_symbol_table: GlobalSymbolTable):
        self.symbol_table = global_symbol_table
        self.cross_file_edges: List[GraphEdge] = []
    
    def link_imports_to_exports(self):
        """Create edges from imports to their exported definitions"""
        for module in self.symbol_table.modules.values():
            for imported in module.imports:
                # Resolve import to file
                target_file = self.symbol_table.resolve_import(
                    module.file_path,
                    imported.source_module,
                    imported.name
                )
                
                if not target_file:
                    # External dependency or unresolved
                    continue
                
                target_module = self.symbol_table.file_to_module.get(target_file)
                if not target_module:
                    continue
                
                # Find matching export
                if imported.is_wildcard:
                    # Import * - link to all exports
                    for export in target_module.exports:
                        self._create_import_edge(imported, export)
                elif imported.name == "default":
                    # Default import
                    default_exports = [e for e in target_module.exports if e.is_default]
                    for export in default_exports:
                        self._create_import_edge(imported, export)
                else:
                    # Named import
                    matching_exports = [
                        e for e in target_module.exports
                        if e.name == imported.name
                    ]
                    for export in matching_exports:
                        self._create_import_edge(imported, export)
    
    def _create_import_edge(
        self,
        imported: ImportedSymbol,
        exported: ExportedSymbol
    ):
        """Create IMPORT_CALL edge"""
        edge = GraphEdge(
            **{
                "from": imported.node_id,
                "to": exported.node_id,
                "type": EdgeType.IMPORTS
            }
        )
        if edge.metadata is None:
            edge.metadata = {}
        edge.metadata.update({
            "source_file": imported.file_path,
            "target_file": exported.file_path,
            "symbol_name": exported.name,
            "import_type": imported.import_type.value if hasattr(imported.import_type, 'value') else imported.import_type,
            "alias": imported.alias,
            "cross_file_edge_type": "IMPORT_CALL"
        })
        self.cross_file_edges.append(edge)
    
    def link_export_to_usages(self):
        """Create edges from exports to their usages in importing files"""
        # For each export, find all imports that reference it
        for module in self.symbol_table.modules.values():
            for exported in module.exports:
                # Find all imports that reference this export
                for importing_module in self.symbol_table.modules.values():
                    if importing_module.file_path == module.file_path:
                        continue  # Skip same file
                    
                    for imported in importing_module.imports:
                        # Check if this import references our export
                        if self._import_references_export(imported, exported, importing_module):
                            # Find usages of the imported symbol in the importing file
                            usages = self._find_symbol_usages(
                                imported,
                                importing_module.cpg
                            )
                            
                            for usage_node_id in usages:
                                self._create_export_ret_edge(
                                    exported,
                                    usage_node_id,
                                    importing_module.file_path
                                )
    
    def _import_references_export(
        self,
        imported: ImportedSymbol,
        exported: ExportedSymbol,
        importing_module: ModuleDefinition
    ) -> bool:
        """Check if import references this export"""
        # Resolve import to file
        target_file = self.symbol_table.resolve_import(
            importing_module.file_path,
            imported.source_module
        )
        
        if target_file != exported.file_path:
            return False
        
        # Check name match
        if imported.is_wildcard:
            return True
        if imported.name == "default" and exported.is_default:
            return True
        if imported.name == exported.name:
            return True
        
        return False
    
    def _find_symbol_usages(
        self,
        imported: ImportedSymbol,
        cpg: SemanticGraph
    ) -> List[str]:
        """Find all nodes that use the imported symbol"""
        usages = []
        
        # The symbol is used with its alias (if any) or original name
        symbol_name = imported.alias or imported.name
        
        for node in cpg.nodes:
            if node.node_type == "IDENTIFIER" and node.name == symbol_name:
                # Skip the import statement itself
                if node.id != imported.node_id:
                    usages.append(node.id)
        
        return usages
    
    def _create_export_ret_edge(
        self,
        exported: ExportedSymbol,
        usage_node_id: str,
        usage_file: str
    ):
        """Create EXPORT_RET edge"""
        edge = GraphEdge(
            **{
                "from": exported.node_id,
                "to": usage_node_id,
                "type": EdgeType.DATA_FLOW
            }
        )
        if edge.metadata is None:
            edge.metadata = {}
        edge.metadata.update({
            "source_file": exported.file_path,
            "target_file": usage_file,
            "symbol_name": exported.name,
            "cross_file_edge_type": "EXPORT_RET"
        })
        self.cross_file_edges.append(edge)


class MultiFileRepositoryGraph:
    """
    Main class for multi-file repository analysis
    
    Orchestrates:
    1. Repository scanning
    2. Per-file CPG parsing
    3. Global symbol table construction
    4. Import/export resolution
    5. Cross-file edge linking
    6. Multi-file DFG construction
    """
    
    def __init__(
        self,
        repo_path: str,
        exclude_patterns: Optional[List[str]] = None
    ):
        self.repo_path = repo_path
        self.scanner = RepositoryScanner(repo_path, exclude_patterns)
        self.symbol_table = GlobalSymbolTable()
        self.cpg_parser = CPGParser()
        
        # All CPGs combined
        self.all_nodes: List[GraphNode] = []
        self.all_edges: List[GraphEdge] = []
    
    def build(self) -> Dict[str, Any]:
        """
        Build multi-file repository graph
        
        Returns:
            Dict with:
            - modules: List of ModuleDefinition
            - global_cpg: Combined CPG with cross-file edges
            - symbol_table: GlobalSymbolTable
            - statistics: Analysis stats
        """
        print(f"🔍 Scanning repository: {self.repo_path}")
        
        # Step 1: Scan repository
        source_files = self.scanner.scan()
        print(f"  ✓ Found {len(source_files)} source files")
        
        # Step 2: Parse each file
        print(f"\n📊 Parsing files...")
        for i, file_path in enumerate(source_files, 1):
            self._parse_file(file_path)
            if i % 10 == 0:
                print(f"  Progress: {i}/{len(source_files)} files")
        
        print(f"  ✓ Parsed {len(self.symbol_table.modules)} modules")
        
        # Step 3: Link imports to exports
        print(f"\n🔗 Linking cross-file references...")
        linker = CrossFileLinker(self.symbol_table)
        linker.link_imports_to_exports()
        linker.link_export_to_usages()
        
        print(f"  ✓ Created {len(linker.cross_file_edges)} cross-file edges")
        
        # Step 4: Combine all edges
        self.all_edges.extend(linker.cross_file_edges)
        
        # Step 5: Build global CPG
        global_cpg = SemanticGraph(
            nodes=self.all_nodes,
            edges=self.all_edges
        )
        
        stats = self._compute_statistics()
        
        print(f"\n✅ Repository graph complete!")
        print(f"  Modules: {stats['total_modules']}")
        print(f"  Total nodes: {stats['total_nodes']}")
        print(f"  Total edges: {stats['total_edges']}")
        print(f"  Cross-file edges: {stats['cross_file_edges']}")
        print(f"  Exported symbols: {stats['total_exports']}")
        print(f"  Imported symbols: {stats['total_imports']}")
        
        return {
            "modules": list(self.symbol_table.modules.values()),
            "global_cpg": global_cpg,
            "symbol_table": self.symbol_table,
            "statistics": stats
        }
    
    def _parse_file(self, file_path: Path):
        """Parse a single file and add to global symbol table"""
        # Determine language
        language = self._detect_language(file_path)
        
        # Parse CPG
        cpg = self.cpg_parser.parse_file(str(file_path), language)
        
        # Extract imports and exports
        resolver = ImportExportResolver(cpg, str(file_path), language)
        exports = resolver.extract_exports()
        imports = resolver.extract_imports()
        
        # Compute module name
        module_name = self._compute_module_name(file_path)
        
        # Create module definition
        module = ModuleDefinition(
            file_path=str(file_path),
            module_name=module_name,
            language=language,
            exports=exports,
            imports=imports,
            cpg=cpg
        )
        
        # Add to global symbol table
        self.symbol_table.add_module(module)
        
        # Add nodes and edges to global collections
        self.all_nodes.extend(cpg.nodes)
        self.all_edges.extend(cpg.edges)
    
    def _detect_language(self, file_path: Path) -> str:
        """Detect language from file extension"""
        ext = file_path.suffix.lower()
        if ext == '.py':
            return "python"
        elif ext in ('.js', '.jsx'):
            return "javascript"
        elif ext in ('.ts', '.tsx'):
            return "typescript"
        return "unknown"
    
    def _compute_module_name(self, file_path: Path) -> str:
        """Compute module name from file path"""
        # Relative to repo root
        relative = file_path.relative_to(self.repo_path)
        
        # Remove extension
        module_path = str(relative.with_suffix(''))
        
        # Convert path separators to dots (Python) or keep as-is (JS)
        # For simplicity, use path notation
        return module_path.replace('\\', '/')
    
    def _compute_statistics(self) -> Dict[str, Any]:
        """Compute statistics about the repository graph"""
        total_exports = sum(
            len(m.exports)
            for m in self.symbol_table.modules.values()
        )
        
        total_imports = sum(
            len(m.imports)
            for m in self.symbol_table.modules.values()
        )
        
        cross_file_edges = sum(
            1 for e in self.all_edges
            if e.edge_type in [t.value for t in CrossFileEdgeType]
        )
        
        return {
            "total_modules": len(self.symbol_table.modules),
            "total_nodes": len(self.all_nodes),
            "total_edges": len(self.all_edges),
            "cross_file_edges": cross_file_edges,
            "total_exports": total_exports,
            "total_imports": total_imports,
            "python_modules": sum(
                1 for m in self.symbol_table.modules.values()
                if m.language == "python"
            ),
            "javascript_modules": sum(
                1 for m in self.symbol_table.modules.values()
                if m.language in ("javascript", "typescript")
            )
        }
    
    def extract_cross_file_path(
        self,
        source_node_id: str,
        sink_node_id: str,
        max_depth: int = 20
    ) -> List[List[GraphEdge]]:
        """
        Extract data flow paths across files
        
        Args:
            source_node_id: Starting node
            sink_node_id: Target node
            max_depth: Maximum path length
        
        Returns:
            List of paths (each path is list of edges)
        """
        paths = []
        visited = set()
        
        def dfs(current: str, target: str, path: List[GraphEdge], depth: int):
            if depth > max_depth:
                return
            
            if current == target:
                paths.append(list(path))
                return
            
            if current in visited:
                return
            
            visited.add(current)
            
            # Follow all edges (including cross-file)
            for edge in self.all_edges:
                if edge.source == current:
                    path.append(edge)
                    dfs(edge.target, target, path, depth + 1)
                    path.pop()
            
            visited.remove(current)
        
        dfs(source_node_id, sink_node_id, [], 0)
        return paths
