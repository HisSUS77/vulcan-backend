# Tree-sitter Universal Parser - Quick Reference

## Installation (One-Time Setup)

```bash
# 1. Install tree-sitter
pip install tree-sitter

# 2. Build language grammars
python setup_grammars.py

# 3. Verify
python test_files/test_universal_parser.py
```

---

## Basic Usage

### Parse a File
```python
from app.domain.analysis.universal_parser import UniversalParser

parser = UniversalParser()
tree = parser.parse_file("src/app.js")

# Access the tree
for child in tree.children:
    print(f"{child.type} '{child.name}' at line {child.start_point[0]}")
```

### Parse Code String
```python
from app.domain.analysis.universal_parser import LanguageType

code = "function hello() { return 'world'; }"
tree = parser.parse_code(code, LanguageType.JAVASCRIPT, "app.js")
```

### Drop-in Replacement for Old Parser
```python
from app.domain.analysis.parser_adapter import UniversalASTParser

# Works exactly like old ASTParser
parser = UniversalASTParser(language="javascript")
graph = parser.parse(code, "app.js")

# Returns SemanticGraph (GraphNode + GraphEdge)
print(f"Nodes: {len(graph.nodes)}")
```

---

## Language Support

| Language | Extension | LanguageType |
|----------|-----------|--------------|
| Python | `.py`, `.pyw` | `LanguageType.PYTHON` |
| JavaScript | `.js`, `.jsx`, `.mjs`, `.cjs` | `LanguageType.JAVASCRIPT` |
| TypeScript | `.ts`, `.tsx` | `LanguageType.TYPESCRIPT` |
| HTML | `.html`, `.htm` | `LanguageType.HTML` |
| JSON | `.json` | `LanguageType.JSON` |
| YAML | `.yaml`, `.yml` | `LanguageType.YAML` |

---

## Common Patterns

### Find All Functions
```python
def find_functions(tree):
    funcs = []
    if tree.type in ("function_definition", "function_declaration"):
        funcs.append(tree)
    for child in tree.children:
        funcs.extend(find_functions(child))
    return funcs

functions = find_functions(tree)
for func in functions:
    print(f"Function: {func.name} at line {func.start_point[0] + 1}")
```

### Find Dangerous Calls
```python
def find_dangerous(tree):
    if tree.type == "call_expression":
        if tree.name in ("eval", "exec"):
            return [tree]
    return sum([find_dangerous(c) for c in tree.children], [])

dangerous = find_dangerous(tree)
```

### Extract Imports
```python
def get_imports(tree):
    if tree.type in ("import_statement", "import_from_statement"):
        return [tree.source_code.strip()]
    return sum([get_imports(c) for c in tree.children], [])
```

---

## StandardNode Structure

```python
node.type          # "function_definition", "call_expression", etc.
node.name          # Identifier name (if any)
node.start_point   # (line, column) - 0-indexed
node.end_point     # (line, column) - 0-indexed
node.source_code   # Original source text
node.children      # List of child StandardNodes
node.parent        # Parent StandardNode
node.attributes    # Dict of metadata
```

---

## Migration Checklist

- [ ] Install tree-sitter: `pip install tree-sitter`
- [ ] Run setup: `python setup_grammars.py`
- [ ] Update imports:
  ```python
  # OLD
  from app.domain.analysis.ast_parser_enhanced import ASTParser
  
  # NEW
  from app.domain.analysis.parser_adapter import UniversalASTParser as ASTParser
  ```
- [ ] Test: `python test_files/test_universal_parser.py`

---

## Performance Tips

✅ **DO:** Reuse parser instance
```python
parser = UniversalParser()
for file in files:
    tree = parser.parse_file(file)
```

❌ **DON'T:** Create new parser each time
```python
for file in files:
    parser = UniversalParser()  # Slow!
```

---

## Troubleshooting

| Error | Solution |
|-------|----------|
| `tree-sitter not installed` | `pip install tree-sitter` |
| `Grammar file not found` | `python setup_grammars.py` |
| `C compiler not found` (Win) | Install Visual Studio Build Tools |
| `C compiler not found` (Linux) | `sudo apt install build-essential` |
| `C compiler not found` (Mac) | `xcode-select --install` |

---

## Key Differences from Old Parser

| Feature | Old Parser | UniversalParser |
|---------|-----------|-----------------|
| JavaScript | Regex-based ❌ | Full AST ✅ |
| Scope awareness | No ❌ | Yes ✅ |
| Closures | No ❌ | Yes ✅ |
| Destructuring | No ❌ | Yes ✅ |
| Error recovery | Crashes ❌ | Continues ✅ |
| Speed | Slow | 3x faster ⚡ |

---

## Example: Security Scanner

```python
from app.domain.analysis.universal_parser import UniversalParser, LanguageType

def scan_for_vulnerabilities(filepath):
    parser = UniversalParser()
    tree = parser.parse_file(filepath)
    
    issues = []
    
    def scan(node):
        # SQL injection
        if "SELECT" in node.source_code and "+" in node.source_code:
            issues.append({
                "type": "SQL Injection",
                "line": node.start_point[0] + 1,
                "code": node.source_code
            })
        
        # XSS
        if node.type == "call_expression":
            if node.name in ("eval", "innerHTML"):
                issues.append({
                    "type": "XSS/Code Injection",
                    "line": node.start_point[0] + 1,
                    "function": node.name
                })
        
        for child in node.children:
            scan(child)
    
    scan(tree)
    return issues

# Usage
issues = scan_for_vulnerabilities("app.js")
for issue in issues:
    print(f"⚠️ {issue['type']} at line {issue['line']}")
```

---

## API Cheatsheet

```python
# Initialize
parser = UniversalParser()

# Parse
tree = parser.parse_file("app.py")
tree = parser.parse_code(code, LanguageType.JAVASCRIPT)

# Detect language
lang = parser.detect_language("app.js")  # → LanguageType.JAVASCRIPT

# Check support
if parser.is_language_supported(LanguageType.PYTHON):
    tree = parser.parse_code(code, LanguageType.PYTHON)

# Available languages
langs = parser.get_available_languages()
```

---

## Links

- **Full Documentation:** `Document-MarkDowns/TREE_SITTER_UNIVERSAL_PARSER.md`
- **Setup Script:** `setup_grammars.py`
- **Test Suite:** `test_files/test_universal_parser.py`
- **Source Code:** `app/domain/analysis/universal_parser.py`
- **Adapter:** `app/domain/analysis/parser_adapter.py`

---

## Support

For issues or questions:
1. Check full documentation
2. Run test suite
3. Check setup_grammars.py output
4. Report with error message + code sample
