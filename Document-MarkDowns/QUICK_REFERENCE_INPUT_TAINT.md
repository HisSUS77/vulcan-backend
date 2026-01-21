# INPUT-FOCUSED TAINT TRACKING - QUICK REFERENCE

## 🎯 Quick Overview
Vulcan now automatically tracks ALL input sources through your code to dangerous operations, detecting SQL Injection, XSS, Command Injection, and other input-related vulnerabilities.

---

## 📍 What Gets Detected

### ✅ Input Sources (Automatically Tracked)
| Type | Examples | Risk Level |
|------|----------|------------|
| **HTTP GET** | `request.GET['id']`, `req.query.name` | HIGH |
| **HTTP POST** | `request.POST['data']`, `request.form['user']` | HIGH |
| **JSON Body** | `request.json['payload']`, `req.body.data` | HIGH |
| **File Uploads** | `request.FILES['document']`, `file.name` | CRITICAL |
| **Cookies** | `request.cookies['session']` | MEDIUM |
| **Headers** | `request.headers['X-Custom']` | MEDIUM |
| **CLI Args** | `sys.argv[1]`, `sys.argv[2]` | HIGH |
| **User Input** | `input('Enter name: ')`, `raw_input()` | HIGH |
| **Environment** | `os.environ['API_KEY']` | MEDIUM |
| **Files** | `file.read()`, `open('data.txt').read()` | MEDIUM |

### ⚠️ Dangerous Sinks (Operations That Can Cause Vulnerabilities)
| Vulnerability | Operations Detected |
|---------------|---------------------|
| **SQL Injection** | `execute()`, `cursor.execute()`, `query()`, `raw()` |
| **Command Injection** | `os.system()`, `subprocess.run()`, `eval()`, `exec()` |
| **XSS** | `innerHTML`, `document.write()`, `response.write()` |
| **Path Traversal** | `open()`, `file.read()`, `os.remove()`, `shutil.move()` |
| **Deserialization** | `pickle.loads()`, `yaml.load()`, `json.loads()` |

### ✅ Sanitizers (Functions That Make Input Safe)
| Function | Purpose |
|----------|---------|
| `html.escape()` | Prevents XSS |
| `urllib.parse.quote()` | URL encoding |
| `bleach.clean()` | HTML sanitization |
| `validate()`, `sanitize()` | General validation |
| `parameterize()` | SQL parameterization |

---

## 🚨 Vulnerability Examples

### ❌ VULNERABLE: SQL Injection
```python
@app.route('/user')
def get_user():
    user_id = request.GET['id']  # ← INPUT SOURCE
    query = f"SELECT * FROM users WHERE id = {user_id}"  # ← Tainted!
    cursor.execute(query)  # ← DANGEROUS SINK
    return cursor.fetchall()
```
**Detection**: ✅ SQL Injection (HIGH)

### ✅ SAFE: Parameterized Query
```python
@app.route('/user')
def get_user():
    user_id = request.GET['id']  # ← INPUT SOURCE
    query = "SELECT * FROM users WHERE id = %s"  # ← Parameterized
    cursor.execute(query, (user_id,))  # ← SAFE
    return cursor.fetchall()
```
**Detection**: ✅ No vulnerability

---

### ❌ VULNERABLE: Command Injection
```python
def process_file():
    filename = sys.argv[1]  # ← INPUT SOURCE (CLI)
    os.system(f"cat {filename}")  # ← DANGEROUS SINK
```
**Detection**: ✅ Command Injection (CRITICAL)

### ✅ SAFE: Use subprocess with List
```python
def process_file():
    filename = sys.argv[1]  # ← INPUT SOURCE
    subprocess.run(['cat', filename])  # ← SAFE (list args)
```
**Detection**: ✅ No vulnerability

---

### ❌ VULNERABLE: XSS
```python
@app.route('/comment', methods=['POST'])
def post_comment():
    comment = request.POST['comment']  # ← INPUT SOURCE
    html = f"<div>{comment}</div>"  # ← Tainted!
    response.write(html)  # ← DANGEROUS SINK
```
**Detection**: ✅ Cross-Site Scripting (HIGH)

### ✅ SAFE: HTML Escaping
```python
import html

@app.route('/comment', methods=['POST'])
def post_comment():
    comment = request.POST['comment']  # ← INPUT SOURCE
    safe = html.escape(comment)  # ← SANITIZER
    html_output = f"<div>{safe}</div>"  # ← Safe!
    response.write(html_output)
```
**Detection**: ✅ No vulnerability (sanitized)

---

### ❌ VULNERABLE: Path Traversal
```python
@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.FILES['document']  # ← INPUT SOURCE
    path = f"/uploads/{file.name}"  # ← Tainted!
    with open(path, 'wb') as f:  # ← DANGEROUS SINK
        f.write(file.read())
```
**Detection**: ✅ Path Traversal (HIGH)

### ✅ SAFE: Validate Filename
```python
import os

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.FILES['document']
    filename = os.path.basename(file.name)  # ← Remove path
    path = f"/uploads/{filename}"
    with open(path, 'wb') as f:
        f.write(file.read())
```
**Detection**: ✅ Reduced risk (still check filename)

---

## 🔍 How It Works

### 1. Input Detection
System automatically marks these as **TAINT_SOURCE**:
```python
user_input = request.GET['id']  # ← Marked as tainted
```

### 2. Taint Propagation
Taint follows data through operations:
```python
user_input = request.GET['id']     # ← Tainted
upper = user_input.upper()         # ← Still tainted
modified = upper + "_suffix"       # ← Still tainted
final = f"Result: {modified}"      # ← Still tainted
```

### 3. Sink Detection
System flags dangerous operations:
```python
cursor.execute(final)  # ← DANGEROUS SINK detected!
```

### 4. Sanitization
Removes taint when safe functions used:
```python
safe = html.escape(user_input)  # ← Taint removed
output = f"<div>{safe}</div>"   # ← Now safe
```

---

## 📊 Input Type Classification

When input is detected, it's classified:

| Input Pattern | Classification | Example |
|---------------|----------------|---------|
| `request.GET` | `HTTP_GET` | Query parameters |
| `request.POST` | `HTTP_POST` | Form data |
| `request.json` | `HTTP_JSON` | API payloads |
| `request.FILES` | `FILE_UPLOAD` | File uploads |
| `request.cookies` | `COOKIE` | Browser cookies |
| `request.headers` | `HTTP_HEADER` | HTTP headers |
| `sys.argv` | `CLI_ARGUMENT` | Command-line args |
| `input()` | `USER_INPUT` | Interactive input |
| `os.environ` | `ENVIRONMENT` | Env variables |

---

## 🎯 Common Patterns

### Pattern 1: HTTP Endpoint → Database
```python
@app.route('/search')
def search():
    query = request.GET['q']  # INPUT
    sql = f"SELECT * FROM items WHERE name LIKE '%{query}%'"
    results = db.execute(sql)  # VULNERABLE!
```
**Fix**: Use parameterized queries

### Pattern 2: CLI → System Command
```python
import sys
filename = sys.argv[1]  # INPUT
os.system(f"rm {filename}")  # VULNERABLE!
```
**Fix**: Use `subprocess` with list args

### Pattern 3: Upload → File System
```python
file = request.FILES['doc']  # INPUT
path = f"/data/{file.name}"
open(path, 'w')  # VULNERABLE!
```
**Fix**: Validate/sanitize filename

### Pattern 4: JSON API → Code Execution
```python
data = request.json  # INPUT
code = data['script']
eval(code)  # EXTREMELY VULNERABLE!
```
**Fix**: Never use eval() on user input

---

## 🧪 Testing Your Code

### Run Taint Tracking Tests
```bash
cd c:\Users\huzai\Desktop\fyp\Vulcan\vulcan-backend\vulcan-backend
.venv\Scripts\python.exe test_files/test_input_taint_tracking.py
```

### Analyze Your Code
```python
from app.domain.analysis.semantic_graph_builder import SemanticGraphBuilder
from app.enums.node_type import NodeType
from app.enums.edge_type import EdgeType

# Your vulnerable code
code = """
@app.route('/api')
def api():
    data = request.GET['data']
    os.system(f"echo {data}")
"""

# Build graph
builder = SemanticGraphBuilder()
graph = builder.build(code, "my_endpoint.py")

# Check for vulnerabilities
input_sources = [n for n in graph.nodes if n.type == NodeType.TAINT_SOURCE]
sinks = [n for n in graph.nodes if n.type == NodeType.SENSITIVE_SINK]
taint_flows = [e for e in graph.edges if e.type == EdgeType.TAINT_FLOW]

print(f"Input sources found: {len(input_sources)}")
print(f"Dangerous sinks found: {len(sinks)}")
print(f"Taint flows: {len(taint_flows)}")

if len(input_sources) > 0 and len(sinks) > 0:
    print("⚠️ VULNERABILITY DETECTED!")
```

---

## 🔧 Configuration

### Extend Input Patterns (if needed)
```python
# In dfg_builder.py
INPUT_SOURCE_PATTERNS = {
    'request.GET',
    'request.POST',
    # Add your custom patterns
    'my_framework.get_input',
    'custom_input_source',
}
```

### Add Custom Sanitizers
```python
# In dfg_builder.py
SANITIZERS = {
    'html.escape',
    'bleach.clean',
    # Add your custom sanitizers
    'my_sanitize_function',
    'custom_validator',
}
```

### Add Custom Sinks
```python
# In dfg_builder.py
DANGEROUS_SINKS = {
    'execute',
    'os.system',
    # Add your custom dangerous operations
    'my_dangerous_function',
    'custom_sql_exec',
}
```

---

## 📈 Best Practices

### ✅ DO
- Use parameterized queries for SQL
- Validate and sanitize ALL user input
- Use safe APIs (subprocess with list, not shell=True)
- Escape output when rendering HTML
- Use allowlists for filenames/paths
- Apply principle of least privilege

### ❌ DON'T
- Use string formatting for SQL queries
- Trust user input without validation
- Use `eval()` or `exec()` on user data
- Concatenate user input into system commands
- Allow arbitrary file paths from users
- Expose detailed error messages to users

---

## 🚀 Quick Wins

### 1. Find All SQL Injection Risks
```bash
# System will detect patterns like:
f"SELECT * FROM table WHERE id = {user_input}"
query.format(user_id)
f"INSERT INTO users VALUES ('{data}')"
```

### 2. Find All Command Injection Risks
```bash
# System will detect patterns like:
os.system(f"command {user_input}")
subprocess.call(f"rm {filename}", shell=True)
eval(user_code)
```

### 3. Find All XSS Risks
```bash
# System will detect patterns like:
response.write(f"<div>{user_comment}</div>")
innerHTML = user_data
document.write(unsanitized)
```

---

## 📞 Need Help?

### Check Test Examples
See `test_files/test_input_taint_tracking.py` for 8 comprehensive examples

### Review Documentation
- [INPUT_TAINT_TRACKING_COMPLETE.md](INPUT_TAINT_TRACKING_COMPLETE.md) - Full details
- [MULTILANG_UPGRADE_COMPLETE.md](MULTILANG_UPGRADE_COMPLETE.md) - Language support

### Understanding Results
- **INPUT_SOURCE** = Where dangerous data enters
- **SENSITIVE_SINK** = Where it can cause damage
- **TAINT_FLOW** = Path from source to sink
- **SANITIZED** = Input was properly cleaned

---

**Quick Start**: Just run your scan - the system automatically tracks all inputs and flags vulnerabilities! 🎯
