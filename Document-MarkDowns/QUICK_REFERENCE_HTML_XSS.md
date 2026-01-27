# Quick Reference: HTML + Backend XSS Analysis

## Quick Start

```python
from app.domain.analysis.html_parser import HTMLParser
from app.domain.analysis.html_backend_linker import HTMLBackendLinker, extract_xss_paths

# 1. Parse HTML
parser = HTMLParser("templates/user.html", html_content)
html_graph = parser.parse()

# 2. Parse Backend
from app.domain.analysis.cpg_parser import CPGParser, LanguageType
cpg_parser = CPGParser()
backend_graph = cpg_parser.parse_file("app.py", LanguageType.PYTHON)

# 3. Link & Detect XSS
linker = HTMLBackendLinker(html_graph, backend_graph, "templates/user.html", ["app.py"])
cross_file_edges = linker.link()
xss_paths = extract_xss_paths(html_graph, backend_graph, cross_file_edges)
```

## Template Syntax Detection

| Engine | Safe | Unsafe (XSS Sink) |
|--------|------|-------------------|
| Jinja2 | `{{ var }}` | `{{ var\|safe }}` |
| Django | `{{ var }}` | `{{ var\|safe }}` |
| EJS | `<%= var %>` | `<%- var %>` |
| Handlebars | `{{ var }}` | `{{{ var }}}` |
| JSX | - | `{var}`, `dangerouslySetInnerHTML` |

## XSS Source Detection

- HTML forms: `<form action="/submit">`
- Input fields: `<input name="username">`
- Textareas: `<textarea name="comment">`
- Event handlers: `onclick="handler()"`

## XSS Sink Detection

- Unescaped template variables
- innerHTML assignments
- eval() calls
- document.write()

## Route Pattern Matching

```python
# Flask
@app.route('/user/<id>')

# Express
app.get('/user/:id', handler)

# Django
path('user/<int:id>/', view)
```

## Graph Schema

**Node Types**:
- `NodeType.IDENTIFIER`: Inputs, variables
- `NodeType.EXPRESSION`: Forms, handlers

**Security Roles**:
- `security_role="source"`: User input
- `security_role="sink"`: Unsafe output

**HTML Metadata** (in `node.value`):
```python
{
    'html_node_type': 'HTML_FORM' | 'HTML_INPUT' | 'HTML_TEMPLATE_VAR',
    'form_action': '/submit',
    'input_type': 'text',
    'template_var': 'username',
    'is_safe_output': False
}
```

## Cross-File Edges

- `FORM_TO_ROUTE`: HTML form → Backend handler
- `DATA_TO_TEMPLATE`: Backend variable → Template variable

## Run Examples

```bash
# Set UTF-8 encoding (Windows)
$env:PYTHONIOENCODING="utf-8"

# Run all examples
python examples/html_xss_examples.py
```

## Supported Features

✅ 7 template engines (Jinja2, EJS, Django, Handlebars, JSX, Mustache, Pug)  
✅ 20+ event handler types  
✅ Flask, Express, Django route detection  
✅ Safe vs. unsafe output detection  
✅ Complete XSS path extraction  
✅ Framework-agnostic design
