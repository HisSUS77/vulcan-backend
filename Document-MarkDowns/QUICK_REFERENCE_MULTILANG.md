# Quick Reference: Multi-Language AST Parser Usage

## New NodeType Values

```python
from app.enums.node_type import NodeType

# New node types you can now detect:
NodeType.IMPORT           # import statements
NodeType.ASYNC_FUNCTION   # async def foo()
NodeType.AWAIT            # await expression
NodeType.LAMBDA           # lambda x: x
NodeType.LIST_COMP        # [x for x in list]
NodeType.DICT_COMP        # {k:v for k,v in dict}
NodeType.SET_COMP         # {x for x in set}
NodeType.GENERATOR_EXP    # (x for x in gen)
NodeType.TRY              # try block
NodeType.EXCEPT           # except handler
NodeType.RAISE            # raise exception
NodeType.GLOBAL           # global var
NodeType.NONLOCAL         # nonlocal var
NodeType.ATTRIBUTE        # obj.attr
```

## Using the Enhanced Parser

### Python (Full AST)
```python
from app.domain.analysis.ast_parser_enhanced import ASTParser

parser = ASTParser(language="python")
graph = parser.parse(code, "app.py")

# Graph now contains all new node types:
for node in graph.nodes:
    if node.type == NodeType.ASYNC_FUNCTION:
        print(f"Found async function: {node.name}")
    elif node.type == NodeType.IMPORT:
        print(f"Found import: {node.name}")
```

### JavaScript/TypeScript (Regex-based)
```python
parser = ASTParser(language="javascript")  # or "typescript", "js", "ts"
graph = parser.parse(js_code, "app.js")

# Detects: imports, functions, assignments, dangerous calls
```

## Language Auto-Detection

```python
from semantic_engine.classifier.llm_service import LLMService

llm = LLMService()
detected_lang = llm._detect_language(code)

# Returns: "python", "javascript", or "typescript"
```

## End-to-End Pipeline

```python
from semantic_engine.pipeline import get_pipeline

pipeline = get_pipeline()

# Python
result = await pipeline.analyze_code(
    filename="app.py",
    code=python_code,
    language="python"
)

# JavaScript
result = await pipeline.analyze_code(
    filename="app.js",
    code=js_code,
    language="javascript"
)
```

## Security Query Patterns

Update `queries/queries.json` to leverage new node types:

```json
{
  "ASYNC_INJECTION": {
    "rule_id": "ASYNC_INJECTION",
    "name": "Async Function Injection",
    "sources": ["request.GET", "request.POST", "PARAMETER"],
    "sinks": ["execute", "eval", "os.system"],
    "patterns": ["DFG_FLOW", "TAINT_FLOW"],
    "confidence": "high"
  }
}
```

## Testing

```bash
# Run comprehensive test suite
python test_files/test_multilang_pipeline.py

# Expected: 6/6 tests pass ✅
```

## Code Examples

### Detect Async SQL Injection
```python
code = """
async def get_user(user_id):
    query = f"SELECT * FROM users WHERE id={user_id}"
    await cursor.execute(query)
"""

result = await pipeline.analyze_code("test.py", code, "python")
# Should detect: SQL Injection via ASYNC_FUNCTION
```

### Detect Lambda Command Injection
```python
code = """
exec_cmd = lambda cmd: os.system(cmd)
user_input = input("Command: ")
exec_cmd(user_input)
"""

result = await pipeline.analyze_code("test.py", code, "python")
# Should detect: Command Injection via LAMBDA
```

### Detect Import-based Threats
```python
code = """
import pickle
user_data = request.GET['data']
obj = pickle.loads(user_data)  # Insecure deserialization
"""

result = await pipeline.analyze_code("test.py", code, "python")
# Should detect: INSECURE_DESERIALIZATION via IMPORT tracking
```

## CFG Integration

New node types automatically included in control flow:

```python
from app.domain.analysis.cfg_builder import CFGBuilder

# These node types now have CFG_NEXT edges:
# - IMPORT
# - TRY, EXCEPT, RAISE
# - AWAIT
# - GLOBAL, NONLOCAL
```

## Troubleshooting

### Issue: "ModuleNotFoundError: No module named 'app.domain.analysis.ast_parser_enhanced'"

**Solution:** File exists, check imports. Should be:
```python
from app.domain.analysis.ast_parser_enhanced import ASTParser
```

### Issue: JavaScript code parsed as Python

**Solution:** Explicitly set language:
```python
graph = parser.parse(code, filename="app.js")  # Wrong
graph = ASTParser(language="javascript").parse(code, "app.js")  # Correct
```

### Issue: Attributes not tracked in DFG

**Known limitation:** ATTRIBUTE nodes are in AST but need DFG enhancement.
Track this issue for future updates.

## What's Next?

1. **Improve JS Parser:** Replace regex with `esprima` or `acorn` library
2. **Add JS Security Rules:** Create JavaScript-specific queries
3. **Cross-File Analysis:** Track imports across files
4. **TypeScript Types:** Parse type annotations

---

**Documentation:**
- Full upgrade details: [MULTILANG_UPGRADE_COMPLETE.md](MULTILANG_UPGRADE_COMPLETE.md)
- Test suite: [test_files/test_multilang_pipeline.py](test_files/test_multilang_pipeline.py)
- Enhanced parser: [app/domain/analysis/ast_parser_enhanced.py](app/domain/analysis/ast_parser_enhanced.py)
