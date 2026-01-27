# Code Property Graph (CPG) Parser Guide

## Overview

The CPG Parser is a production-grade static analysis engine built with Tree-sitter, inspired by **Joern** and **CodeQL**. It extracts comprehensive Code Property Graphs from JavaScript and TypeScript codebases, enabling advanced security analysis, vulnerability detection, and code quality assessment.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      CPG Parser System                       │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────┐      ┌──────────────┐      ┌────────────┐ │
│  │ Tree-sitter │──────▶│  CPGParser   │──────▶│ CPG Output │ │
│  │  (JS/TS)    │ AST  │   (Core)     │ CPG  │   (Graph)  │ │
│  └─────────────┘      └──────────────┘      └────────────┘ │
│                              │                               │
│                              │                               │
│                    ┌─────────▼──────────┐                   │
│                    │  Scope Tracker     │                   │
│                    │  Symbol Table      │                   │
│                    │  Reference Tracker │                   │
│                    └─────────┬──────────┘                   │
│                              │                               │
│                              │                               │
│                    ┌─────────▼──────────┐                   │
│                    │  CFG Builder       │                   │
│                    │  DFG Builder       │                   │
│                    └────────────────────┘                   │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

## Key Features

### 1. **Comprehensive AST Extraction**
- Full Tree-sitter integration for JS/TS
- Error-tolerant parsing (handles syntax errors gracefully)
- Preserves source code ranges and positions
- Parent-child relationship tracking

### 2. **Lexical Scope Tracking**
- Global scope
- Function scopes (including arrow functions)
- Block scopes (if/for/while blocks)
- Class scopes
- Closure detection

### 3. **Symbol Table Construction**
- Variable declarations (var, let, const)
- Function declarations and expressions
- Class declarations
- Import/export statements
- Symbol references tracking (def-use chains)

### 4. **Advanced Node Extraction**
- ✅ Function declarations
- ✅ Arrow functions
- ✅ Async/await functions
- ✅ Generator functions
- ✅ Class declarations
- ✅ Class methods (public/private)
- ✅ Import statements (default, named, namespace)
- ✅ Export statements (default, named)
- ✅ Call expressions
- ✅ Member access chains (obj.prop.method)
- ✅ Variable declarations
- ✅ Identifiers (references)

### 5. **Control Flow Graph (CFG)**
- Sequential execution edges
- Conditional branches (if/else)
- Loop structures (for/while/do-while)
- Entry and exit nodes
- True/false branch labels

### 6. **Data Flow Graph (DFG)**
- Variable definition points
- Variable use points
- Def-use chains
- Reaching definitions analysis
- Scope-aware data flow

## Data Model

### GraphNode

```python
class GraphNode(BaseModel):
    id: str                      # Unique node identifier
    type: NodeType               # Node type (FUNCTION, CLASS, etc.)
    name: Optional[str]          # Node name (function/class name)
    file: str                    # Source file path
    line: int                    # Line number (1-based)
    column: int                  # Column number (1-based)
    source_code: Optional[str]   # Original source code
    parent_id: Optional[str]     # Parent node ID
    child_ids: List[str]         # Child node IDs
    metadata: Optional[NodeMetadata]
```

### NodeMetadata

```python
class NodeMetadata(BaseModel):
    scope_id: Optional[str]      # Lexical scope identifier
    symbol_name: Optional[str]   # Symbol name in symbol table
    is_exported: bool            # Whether exported from module
    is_async: bool               # Whether async function
    is_generator: bool           # Whether generator function
    visibility: Optional[str]    # public/private/protected
    start_byte: Optional[int]    # Start byte position
    end_byte: Optional[int]      # End byte position
```

### GraphEdge

```python
class GraphEdge(BaseModel):
    id: str                      # Unique edge identifier
    from_node: str               # Source node ID
    to_node: str                 # Target node ID
    type: EdgeType               # Edge type (CALLS, CONTROL_FLOW, etc.)
    label: Optional[str]         # Edge label (variable name, condition)
    order: Optional[int]         # Edge ordering
```

### SemanticGraph (CPG)

```python
class SemanticGraph(BaseModel):
    nodes: List[GraphNode]       # All nodes in the graph
    edges: List[GraphEdge]       # All edges in the graph
    symbol_table: Dict[str, List[SymbolReference]]
    scopes: Dict[str, Dict[str, Any]]
```

## Node Types

```python
class NodeType(str, Enum):
    # Core structures
    FUNCTION = "function"
    ASYNC_FUNCTION = "async_function"
    ARROW_FUNCTION = "arrow_function"
    GENERATOR_FUNCTION = "generator_function"
    CLASS = "class"
    METHOD = "method"
    
    # Declarations
    VARIABLE_DECLARATION = "variable_declaration"
    IDENTIFIER = "identifier"
    
    # Imports/Exports
    IMPORT = "import"
    EXPORT = "export"
    
    # Expressions
    CALL_EXPRESSION = "call_expression"
    MEMBER_ACCESS = "member_access"
    EXPRESSION = "expression"
    
    # Control flow
    IF_STATEMENT = "if_statement"
    FOR_LOOP = "for_loop"
    WHILE_LOOP = "while_loop"
    RETURN_STATEMENT = "return_statement"
```

## Edge Types

```python
class EdgeType(str, Enum):
    # Structural
    CONTAINS = "contains"
    PARENT_OF = "parent_of"
    
    # Call graph
    CALLS = "calls"
    CALLED_BY = "called_by"
    
    # Data flow
    DEFINES = "defines"
    USES = "uses"
    DATA_FLOW = "data_flow"
    
    # Control flow
    CONTROL_FLOW = "control_flow"
    
    # Dependencies
    IMPORTS = "imports"
    EXPORTS = "exports"
```

## Usage Examples

### Basic Parsing

```python
from app.domain.analysis.cpg_parser import CPGParser, LanguageType

# Create parser instance
parser = CPGParser()

# Parse JavaScript file
cpg = parser.parse_file("app.js", LanguageType.JAVASCRIPT)

# Parse TypeScript code
typescript_code = """
async function fetchUser(id: number): Promise<User> {
    const response = await fetch(`/api/users/${id}`);
    return response.json();
}
"""
cpg = parser.parse_code(typescript_code, LanguageType.TYPESCRIPT, "api.ts")

# Inspect results
print(f"Nodes: {len(cpg.nodes)}")
print(f"Edges: {len(cpg.edges)}")
print(f"Scopes: {len(cpg.scopes)}")
print(f"Symbols: {len(cpg.symbol_table)}")
```

### Extract Specific Nodes

```python
from app.enums.node_type import NodeType

# Find all functions
functions = [n for n in cpg.nodes if n.type == NodeType.FUNCTION]
for func in functions:
    print(f"Function: {func.name} at line {func.line}")

# Find async functions
async_funcs = [n for n in cpg.nodes if n.metadata and n.metadata.is_async]
for func in async_funcs:
    print(f"Async function: {func.name}")

# Find exported symbols
exports = [n for n in cpg.nodes if n.metadata and n.metadata.is_exported]
for exp in exports:
    print(f"Exported: {exp.name}")
```

### Analyze Call Expressions

```python
# Find all call expressions
calls = [n for n in cpg.nodes if n.type == NodeType.CALL_EXPRESSION]

# Find dangerous calls
dangerous = ["eval", "exec", "Function", "innerHTML"]
risky_calls = [c for c in calls if any(d in (c.name or "") for d in dangerous)]

for call in risky_calls:
    print(f"⚠️  Dangerous call: {call.name}() at line {call.line}")
    print(f"   Code: {call.source_code}")
```

### Detect SQL Injection Vulnerabilities

```python
# Find potential SQL injections
for node in cpg.nodes:
    if node.source_code and any(sql in node.source_code for sql in ["SELECT", "INSERT", "UPDATE", "DELETE"]):
        # Check for string concatenation or template literals
        if "${" in node.source_code or "+" in node.source_code:
            print(f"🔴 Potential SQL injection at line {node.line}")
            print(f"   Code: {node.source_code}")
```

### Extract CFG and DFG

```python
from app.domain.analysis.cfg_dfg_extractor import extract_cfg_dfg

# Parse code
cpg = parser.parse_file("app.js", LanguageType.JAVASCRIPT)

# Extract control flow and data flow
enhanced_cpg = extract_cfg_dfg(cpg)

# Analyze control flow edges
from app.enums.edge_type import EdgeType
cf_edges = [e for e in enhanced_cpg.edges if e.type == EdgeType.CONTROL_FLOW]
print(f"Control flow edges: {len(cf_edges)}")

# Analyze data flow edges
df_edges = [e for e in enhanced_cpg.edges if e.type == EdgeType.DATA_FLOW]
print(f"Data flow edges: {len(df_edges)}")

# Trace data flow for a variable
def trace_data_flow(var_name):
    """Trace all data flows for a variable"""
    flows = [e for e in df_edges if e.label == var_name]
    for edge in flows:
        from_node = next(n for n in enhanced_cpg.nodes if n.id == edge.from_node)
        to_node = next(n for n in enhanced_cpg.nodes if n.id == edge.to_node)
        print(f"{from_node.name} -> {to_node.name} [{var_name}]")

trace_data_flow("userId")
```

### Scope Analysis

```python
# Analyze scope hierarchy
def print_scope_tree(scopes, scope_id="global", indent=0):
    """Recursively print scope hierarchy"""
    scope = scopes[scope_id]
    print("  " * indent + f"- {scope_id} ({scope['type']})")
    
    # Print symbols in this scope
    for symbol in scope.get('symbols', {}).keys():
        print("  " * (indent + 1) + f"* {symbol}")
    
    # Find child scopes
    for child_id, child_scope in scopes.items():
        if child_scope.get('parent') == scope_id:
            print_scope_tree(scopes, child_id, indent + 1)

print_scope_tree(cpg.scopes)
```

### Symbol Reference Tracking

```python
# Find all references to a symbol
def find_references(symbol_name):
    """Find all references to a symbol"""
    if symbol_name in cpg.symbol_table:
        refs = cpg.symbol_table[symbol_name]
        print(f"Symbol '{symbol_name}' has {len(refs)} references:")
        for ref in refs:
            print(f"  - {ref['type']} at line {ref['line']}")
    else:
        print(f"Symbol '{symbol_name}' not found")

find_references("getUserById")
```

### Export to JSON

```python
import json

# Convert CPG to JSON
cpg_json = {
    "nodes": [
        {
            "id": n.id,
            "type": n.type.value,
            "name": n.name,
            "line": n.line,
            "source_code": n.source_code
        }
        for n in cpg.nodes
    ],
    "edges": [
        {
            "from": e.from_node,
            "to": e.to_node,
            "type": e.type.value,
            "label": e.label
        }
        for e in cpg.edges
    ],
    "symbol_table": cpg.symbol_table,
    "scopes": cpg.scopes
}

# Save to file
with open("cpg_output.json", "w") as f:
    json.dump(cpg_json, f, indent=2)
```

## Security Analysis Examples

### 1. Taint Analysis

```python
def taint_analysis(cpg, source_functions, sink_functions):
    """
    Perform taint analysis to find vulnerable data flows
    
    Args:
        source_functions: Functions that introduce tainted data (e.g., req.body, req.query)
        sink_functions: Dangerous functions (e.g., db.query, eval)
    """
    from app.enums.edge_type import EdgeType
    
    # Find source nodes
    sources = []
    for node in cpg.nodes:
        if node.type == NodeType.CALL_EXPRESSION:
            if any(src in (node.name or "") for src in source_functions):
                sources.append(node)
    
    # Find sink nodes
    sinks = []
    for node in cpg.nodes:
        if node.type == NodeType.CALL_EXPRESSION:
            if any(sink in (node.name or "") for sink in sink_functions):
                sinks.append(node)
    
    # Trace data flow from sources to sinks
    vulnerabilities = []
    for source in sources:
        for sink in sinks:
            path = find_data_flow_path(cpg, source.id, sink.id)
            if path:
                vulnerabilities.append({
                    "source": source.name,
                    "sink": sink.name,
                    "path": path
                })
    
    return vulnerabilities

# Example usage
sources = ["req.body", "req.query", "req.params"]
sinks = ["db.query", "eval", "exec", "innerHTML"]
vulns = taint_analysis(cpg, sources, sinks)

for vuln in vulns:
    print(f"🔴 Vulnerability: {vuln['source']} -> {vuln['sink']}")
    print(f"   Path: {' -> '.join(vuln['path'])}")
```

### 2. Authentication Check Analysis

```python
def check_missing_auth(cpg):
    """Find API endpoints without authentication checks"""
    
    # Find all route handlers (e.g., app.get, app.post)
    routes = []
    for node in cpg.nodes:
        if node.type == NodeType.CALL_EXPRESSION:
            if node.name and any(method in node.name for method in ["app.get", "app.post", "app.put", "app.delete"]):
                routes.append(node)
    
    # Check if route has auth middleware
    vulnerable_routes = []
    for route in routes:
        # Find function scope
        scope_id = route.metadata.scope_id if route.metadata else None
        if scope_id:
            # Check if auth functions are called in this scope
            has_auth = False
            for node in cpg.nodes:
                if node.metadata and node.metadata.scope_id == scope_id:
                    if node.type == NodeType.CALL_EXPRESSION:
                        if "verify" in (node.name or "") or "authenticate" in (node.name or ""):
                            has_auth = True
                            break
            
            if not has_auth:
                vulnerable_routes.append(route)
    
    return vulnerable_routes

# Example usage
unprotected = check_missing_auth(cpg)
for route in unprotected:
    print(f"⚠️  Unprotected route at line {route.line}")
    print(f"   Code: {route.source_code}")
```

### 3. Code Complexity Analysis

```python
def calculate_cyclomatic_complexity(cpg):
    """Calculate cyclomatic complexity for each function"""
    from app.enums.edge_type import EdgeType
    
    functions = [n for n in cpg.nodes if n.type in (NodeType.FUNCTION, NodeType.ASYNC_FUNCTION)]
    
    complexity_scores = []
    for func in functions:
        # Count decision points in function scope
        decision_points = 0
        scope_id = func.metadata.scope_id if func.metadata else None
        
        if scope_id:
            for node in cpg.nodes:
                if node.metadata and node.metadata.scope_id == scope_id:
                    if node.type in (NodeType.IF_STATEMENT, NodeType.FOR_LOOP, NodeType.WHILE_LOOP):
                        decision_points += 1
        
        complexity = decision_points + 1  # Base complexity
        complexity_scores.append({
            "function": func.name,
            "complexity": complexity,
            "line": func.line
        })
    
    return sorted(complexity_scores, key=lambda x: x["complexity"], reverse=True)

# Example usage
scores = calculate_cyclomatic_complexity(cpg)
for score in scores[:10]:  # Top 10 most complex
    status = "🔴" if score["complexity"] > 10 else "🟡" if score["complexity"] > 5 else "🟢"
    print(f"{status} {score['function']}: complexity={score['complexity']} at line {score['line']}")
```

## Integration with Vulcan

### Scan Service Integration

```python
from app.services.scan_service import ScanService
from app.domain.analysis.cpg_parser import CPGParser, LanguageType

class EnhancedScanService(ScanService):
    def __init__(self):
        super().__init__()
        self.cpg_parser = CPGParser()
    
    async def scan_javascript_file(self, file_path: str):
        """Scan JavaScript/TypeScript file using CPG parser"""
        
        # Parse with CPG
        cpg = self.cpg_parser.parse_file(file_path, LanguageType.JAVASCRIPT)
        
        # Extract CFG/DFG
        from app.domain.analysis.cfg_dfg_extractor import extract_cfg_dfg
        cpg = extract_cfg_dfg(cpg)
        
        # Run vulnerability detection
        vulnerabilities = []
        
        # SQL injection detection
        sql_vulns = self._detect_sql_injection(cpg)
        vulnerabilities.extend(sql_vulns)
        
        # XSS detection
        xss_vulns = self._detect_xss(cpg)
        vulnerabilities.extend(xss_vulns)
        
        # Command injection
        cmd_vulns = self._detect_command_injection(cpg)
        vulnerabilities.extend(cmd_vulns)
        
        return {
            "file": file_path,
            "vulnerabilities": vulnerabilities,
            "cpg_stats": {
                "nodes": len(cpg.nodes),
                "edges": len(cpg.edges),
                "functions": len([n for n in cpg.nodes if n.type == NodeType.FUNCTION])
            }
        }
```

## Performance Considerations

1. **Memory Usage**: CPG can be large for big codebases. Consider:
   - Parsing files incrementally
   - Streaming results
   - Limiting scope depth for analysis

2. **Parse Time**: Tree-sitter is fast, but parsing many files takes time:
   - Use parallel processing for multi-file projects
   - Cache parsed CPGs
   - Implement incremental parsing for file changes

3. **Graph Size**: CFG/DFG can explode graph size:
   - Extract CFG/DFG only when needed
   - Prune unnecessary edges
   - Use graph compression techniques

## Comparison to Other Tools

| Feature | Vulcan CPG Parser | Joern | CodeQL |
|---------|-------------------|-------|--------|
| Languages | JS/TS (extensible) | Java, C, C++, JS, Python | 15+ languages |
| Graph Type | CPG + CFG + DFG | CPG | QL database |
| Query Language | Python API | Joern Query Language | QL |
| Error Tolerance | ✅ High | ❌ Low | ✅ Medium |
| Scope Tracking | ✅ Full | ✅ Full | ✅ Full |
| Symbol Resolution | ✅ Yes | ✅ Yes | ✅ Yes |
| Integration | FastAPI/Python | Standalone/Scala | GitHub Actions |
| License | MIT | Apache 2.0 | Proprietary |

## Future Enhancements

- [ ] Add Python language support
- [ ] Implement query language (similar to Joern QL)
- [ ] Add more advanced data flow analysis (inter-procedural)
- [ ] Call graph construction
- [ ] Type inference for JavaScript
- [ ] Support for React/Vue components
- [ ] Integration with external tools (SARIF output)
- [ ] Web UI for graph visualization
- [ ] Custom query templates for common vulnerabilities

## References

- [Tree-sitter Documentation](https://tree-sitter.github.io/tree-sitter/)
- [Joern Documentation](https://joern.io/)
- [CodeQL Documentation](https://codeql.github.com/)
- [Code Property Graph Paper](https://www.sec.cs.tu-bs.de/pubs/2014-ieeesp.pdf)

---

**Last Updated**: 2024
**Status**: Production Ready ✅
