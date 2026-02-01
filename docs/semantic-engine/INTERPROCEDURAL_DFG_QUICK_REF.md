# Interprocedural DFG - Quick Reference

## 🚀 Quick Start

```python
from app.domain.analysis.cpg_parser import CPGParser
from app.domain.analysis.interprocedural_dfg import InterproceduralDFG

# 1. Parse code
parser = CPGParser()
cpg = parser.parse_code(source_code, "python", "app.py")

# 2. Build DFG
dfg = InterproceduralDFG(cpg)
enhanced_cpg = dfg.build()

# 3. Get stats
print(dfg.get_statistics())
```

## 📊 Edge Types Cheat Sheet

| Edge Type | Description | Example |
|-----------|-------------|---------|
| `DFG_ARG_PASS` | Argument → Parameter | `func(x)` → `def func(param)` |
| `DFG_RET` | Return → Call site | `return val` → `result = func()` |
| `DFG_CLOSURE` | Closure capture | Inner function uses outer var |
| `DFG_CALLBACK` | Callback invocation | `callback(data)` in function |
| `DFG_TUPLE_UNPACK` | Tuple unpacking | `a, b = func()` |
| `DFG_VAR_USE` | Variable def-use | `x = 5`; `y = x` |
| `DFG_UNCERTAIN` | Uncertain flow | Dynamic property access |

## ❓ Uncertainty Levels

| Level | Confidence | Example |
|-------|-----------|---------|
| `CERTAIN` | 1.0 | `x = y` |
| `LIKELY` | 0.8 | Callback with known pattern |
| `POSSIBLE` | 0.5 | Dynamic with hints |
| `UNKNOWN` | 0.3 | `eval()`, dynamic imports |

## 🎯 Common Patterns

### Pattern 1: Find Taint Paths
```python
# Extract path from source to sink
paths = dfg.extract_interprocedural_paths(
    source_node_id="node_source",
    sink_node_id="node_sink",
    max_depth=10
)

for path in paths:
    print(f"Confidence: {path.confidence}")
    print(f"Steps: {len(path.path_edges)}")
```

### Pattern 2: Filter by Edge Type
```python
# Find all argument passing edges
arg_edges = [
    e for e in dfg.dfg_edges
    if e.edge_type == "DFG_ARG_PASS"
]
```

### Pattern 3: Get Function Calls
```python
# List all function calls
for call_site in dfg.call_sites:
    print(f"{call_site.caller_function} → {call_site.callee_name}")
    print(f"  Args: {len(call_site.arguments)}")
```

### Pattern 4: Detect Closures
```python
# Find closure captures
for func_id, captured_vars in dfg.closure_captures.items():
    print(f"Function {func_id} captures: {captured_vars}")
```

### Pattern 5: High-Level API
```python
from app.domain.analysis.semantic_graph_builder import SemanticGraphBuilder

# Automatic CPG + DFG
builder = SemanticGraphBuilder(language="python")
graph = builder.build(code, "app.py")
```

## 🔍 Debugging Tips

### Check DFG Statistics
```python
stats = dfg.get_statistics()
print(f"Functions: {stats['total_functions']}")
print(f"Calls: {stats['total_call_sites']}")
print(f"DFG edges: {stats['total_dfg_edges']}")
print(f"Uncertain: {stats['uncertain_edges']}")
```

### Export Enhanced CPG
```python
import json
with open("enhanced_cpg.json", "w") as f:
    json.dump(enhanced_cpg.model_dump(), f, indent=2)
```

### Visualize Edge Types
```python
from collections import Counter
edge_types = Counter(e.edge_type for e in dfg.dfg_edges)
print(edge_types)
```

## 🎨 Language-Specific Features

### Python
- ✅ Tuple unpacking: `a, b, c = func()`
- ✅ Multiple returns: `return x, y, z`
- ✅ Variable def-use chains

### JavaScript
- ✅ Closures: Inner functions capture outer scope
- ✅ Callbacks: Track callback parameter flow
- ✅ Arrow functions: `(x) => x * 2`
- ✅ Async/await patterns

## ⚠️ Limitations

1. **Dynamic imports**: Marked as `DFG_UNCERTAIN`
2. **Reflection APIs**: Low confidence (0.3)
3. **eval/exec**: Cannot determine flow statically
4. **Third-party functions**: No flow info (graceful degradation)

## 📦 Integration Points

### With Taint Analysis
```python
from app.domain.analysis.taint_engine import TaintEngine

taint_engine = TaintEngine()
taint_results = taint_engine.analyze(enhanced_cpg)
```

### With Semantic Graph
```python
# Backward compatible with SemanticGraph
semantic_graph = builder._cpg_to_semantic_graph(enhanced_cpg)
```

### With Vulnerability Detection
```python
# Find SQL injection paths
sql_sinks = ["execute(", ".execute(", "cursor.execute"]
for node in cpg.nodes:
    if any(sink in (node.code or "") for sink in sql_sinks):
        # Check if tainted source reaches this sink
        pass
```

## 🧪 Testing

```bash
# Run all tests
python examples/interprocedural_dfg_examples.py

# Expected output:
# ✅ Python Simple Call
# ✅ JavaScript Closure
# ✅ JavaScript Callback
# ✅ Python Tuple Unpack
# ✅ Multi-Function Path
# ✅ Uncertainty Tracking
# ✅ Complex Interprocedural
```

## 📚 Full Documentation

See [INTERPROCEDURAL_DFG_README.md](INTERPROCEDURAL_DFG_README.md) for:
- Detailed architecture
- Algorithm explanations
- Advanced usage patterns
- Security applications
- Performance optimization

## 🎉 Summary

**What it does**: Tracks data flow across function calls  
**Languages**: Python, JavaScript, TypeScript  
**Special features**: Closures, callbacks, tuple unpacking, uncertainty  
**Integration**: Works with existing CPG parser and semantic graph  
**Use case**: Taint analysis, vulnerability detection, code auditing
