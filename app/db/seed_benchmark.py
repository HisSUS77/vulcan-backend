"""
Seed dataset: 106 labeled Python/JS test cases covering 18 CWEs.
Sources: manual (55), OWASP Benchmark (23), Juliet Test Suite / NIST SARD (28).
Each entry: name, code, language, cwe, vuln_type, label, source
"""

SEED_CASES = [

    # ── CWE-89 SQL Injection (Python) ─────────────────────────────────────────
    {
        "name": "SQLi: f-string query",
        "language": "python",
        "cwe": "CWE-89",
        "vuln_type": "SQL_INJECTION",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "def get_user(username):\n"
            "    query = f\"SELECT * FROM users WHERE name = '{username}'\"\n"
            "    cursor.execute(query)\n"
            "    return cursor.fetchone()\n"
        ),
    },
    {
        "name": "SQLi: string concat query",
        "language": "python",
        "cwe": "CWE-89",
        "vuln_type": "SQL_INJECTION",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "def search(term):\n"
            "    sql = \"SELECT id FROM products WHERE name = '\" + term + \"'\"\n"
            "    cursor.execute(sql)\n"
        ),
    },
    {
        "name": "SQLi: format() query",
        "language": "python",
        "cwe": "CWE-89",
        "vuln_type": "SQL_INJECTION",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "def login(user, pwd):\n"
            "    q = \"SELECT * FROM accounts WHERE user='{}' AND pwd='{}'\".format(user, pwd)\n"
            "    return db.execute(q).fetchone()\n"
        ),
    },
    {
        "name": "SQLi: parameterized query (safe)",
        "language": "python",
        "cwe": "CWE-89",
        "vuln_type": "SQL_INJECTION",
        "label": "safe",
        "source": "manual",
        "code": (
            "def get_user(username):\n"
            "    cursor.execute('SELECT * FROM users WHERE name = %s', (username,))\n"
            "    return cursor.fetchone()\n"
        ),
    },
    {
        "name": "SQLi: ORM query (safe)",
        "language": "python",
        "cwe": "CWE-89",
        "vuln_type": "SQL_INJECTION",
        "label": "safe",
        "source": "manual",
        "code": (
            "def get_user(username):\n"
            "    return db.session.query(User).filter(User.name == username).first()\n"
        ),
    },

    # ── CWE-89 SQL Injection (JavaScript) ────────────────────────────────────
    {
        "name": "SQLi: JS template literal query",
        "language": "javascript",
        "cwe": "CWE-89",
        "vuln_type": "SQL_INJECTION",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "async function getUser(id) {\n"
            "  const result = await db.query(`SELECT * FROM users WHERE id = ${id}`);\n"
            "  return result.rows[0];\n"
            "}\n"
        ),
    },
    {
        "name": "SQLi: JS parameterized (safe)",
        "language": "javascript",
        "cwe": "CWE-89",
        "vuln_type": "SQL_INJECTION",
        "label": "safe",
        "source": "manual",
        "code": (
            "async function getUser(id) {\n"
            "  const result = await db.query('SELECT * FROM users WHERE id = $1', [id]);\n"
            "  return result.rows[0];\n"
            "}\n"
        ),
    },

    # ── CWE-78 Command Injection (Python) ─────────────────────────────────────
    {
        "name": "CmdInjection: os.system with user input",
        "language": "python",
        "cwe": "CWE-78",
        "vuln_type": "COMMAND_INJECTION",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "import os\n"
            "def ping(host):\n"
            "    os.system('ping -c 1 ' + host)\n"
        ),
    },
    {
        "name": "CmdInjection: subprocess shell=True",
        "language": "python",
        "cwe": "CWE-78",
        "vuln_type": "COMMAND_INJECTION",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "import subprocess\n"
            "def run_cmd(cmd):\n"
            "    return subprocess.check_output(cmd, shell=True)\n"
        ),
    },
    {
        "name": "CmdInjection: subprocess list (safe)",
        "language": "python",
        "cwe": "CWE-78",
        "vuln_type": "COMMAND_INJECTION",
        "label": "safe",
        "source": "manual",
        "code": (
            "import subprocess\n"
            "def ping(host):\n"
            "    return subprocess.run(['ping', '-c', '1', host], capture_output=True)\n"
        ),
    },
    {
        "name": "CmdInjection: JS exec with user input",
        "language": "javascript",
        "cwe": "CWE-78",
        "vuln_type": "COMMAND_INJECTION",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "const { exec } = require('child_process');\n"
            "function runFile(filename) {\n"
            "  exec('cat ' + filename, (err, stdout) => console.log(stdout));\n"
            "}\n"
        ),
    },
    {
        "name": "CmdInjection: JS execFile (safe)",
        "language": "javascript",
        "cwe": "CWE-78",
        "vuln_type": "COMMAND_INJECTION",
        "label": "safe",
        "source": "manual",
        "code": (
            "const { execFile } = require('child_process');\n"
            "function runFile(filename) {\n"
            "  execFile('cat', [filename], (err, stdout) => console.log(stdout));\n"
            "}\n"
        ),
    },

    # ── CWE-22 Path Traversal ─────────────────────────────────────────────────
    {
        "name": "PathTraversal: open with user path",
        "language": "python",
        "cwe": "CWE-22",
        "vuln_type": "PATH_TRAVERSAL",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "def read_file(filename):\n"
            "    with open('/var/data/' + filename) as f:\n"
            "        return f.read()\n"
        ),
    },
    {
        "name": "PathTraversal: Flask send_file",
        "language": "python",
        "cwe": "CWE-22",
        "vuln_type": "PATH_TRAVERSAL",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "from flask import request, send_file\n"
            "def download():\n"
            "    fname = request.args.get('file')\n"
            "    return send_file('/uploads/' + fname)\n"
        ),
    },
    {
        "name": "PathTraversal: safe_join (safe)",
        "language": "python",
        "cwe": "CWE-22",
        "vuln_type": "PATH_TRAVERSAL",
        "label": "safe",
        "source": "manual",
        "code": (
            "import os\n"
            "BASE = '/var/data'\n"
            "def read_file(filename):\n"
            "    safe = os.path.realpath(os.path.join(BASE, filename))\n"
            "    if not safe.startswith(BASE):\n"
            "        raise ValueError('Invalid path')\n"
            "    with open(safe) as f:\n"
            "        return f.read()\n"
        ),
    },
    {
        "name": "PathTraversal: JS path join user input",
        "language": "javascript",
        "cwe": "CWE-22",
        "vuln_type": "PATH_TRAVERSAL",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "const fs = require('fs');\n"
            "function readFile(req, res) {\n"
            "  const file = req.query.file;\n"
            "  res.send(fs.readFileSync('/uploads/' + file, 'utf8'));\n"
            "}\n"
        ),
    },

    # ── CWE-79 XSS ───────────────────────────────────────────────────────────
    {
        "name": "XSS: innerHTML with user data",
        "language": "javascript",
        "cwe": "CWE-79",
        "vuln_type": "XSS",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "function showMessage(msg) {\n"
            "  document.getElementById('output').innerHTML = msg;\n"
            "}\n"
        ),
    },
    {
        "name": "XSS: document.write user input",
        "language": "javascript",
        "cwe": "CWE-79",
        "vuln_type": "XSS",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "const name = new URLSearchParams(location.search).get('name');\n"
            "document.write('<h1>Hello ' + name + '</h1>');\n"
        ),
    },
    {
        "name": "XSS: textContent (safe)",
        "language": "javascript",
        "cwe": "CWE-79",
        "vuln_type": "XSS",
        "label": "safe",
        "source": "manual",
        "code": (
            "function showMessage(msg) {\n"
            "  document.getElementById('output').textContent = msg;\n"
            "}\n"
        ),
    },
    {
        "name": "XSS: Python Jinja2 unescaped",
        "language": "python",
        "cwe": "CWE-79",
        "vuln_type": "XSS",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "from flask import request, Markup\n"
            "def greet():\n"
            "    name = request.args.get('name')\n"
            "    return Markup(f'<h1>Hello {name}</h1>')\n"
        ),
    },
    {
        "name": "XSS: Python escape (safe)",
        "language": "python",
        "cwe": "CWE-79",
        "vuln_type": "XSS",
        "label": "safe",
        "source": "manual",
        "code": (
            "from markupsafe import escape\n"
            "from flask import request\n"
            "def greet():\n"
            "    name = escape(request.args.get('name', ''))\n"
            "    return f'<h1>Hello {name}</h1>'\n"
        ),
    },

    # ── CWE-798 Hardcoded Secrets ─────────────────────────────────────────────
    {
        "name": "HardcodedSecret: password in code",
        "language": "python",
        "cwe": "CWE-798",
        "vuln_type": "HARDCODED_SECRETS",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "DB_PASSWORD = 'supersecret123'\n"
            "def connect():\n"
            "    return psycopg2.connect(password=DB_PASSWORD)\n"
        ),
    },
    {
        "name": "HardcodedSecret: API key literal",
        "language": "python",
        "cwe": "CWE-798",
        "vuln_type": "HARDCODED_SECRETS",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "API_KEY = 'sk-proj-abc123xyz'\n"
            "def call_api(prompt):\n"
            "    headers = {'Authorization': f'Bearer {API_KEY}'}\n"
        ),
    },
    {
        "name": "HardcodedSecret: JS token literal",
        "language": "javascript",
        "cwe": "CWE-798",
        "vuln_type": "HARDCODED_SECRETS",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "const SECRET_KEY = 'my-super-secret-jwt-key-12345';\n"
            "function signToken(payload) {\n"
            "  return jwt.sign(payload, SECRET_KEY);\n"
            "}\n"
        ),
    },
    {
        "name": "HardcodedSecret: env var (safe)",
        "language": "python",
        "cwe": "CWE-798",
        "vuln_type": "HARDCODED_SECRETS",
        "label": "safe",
        "source": "manual",
        "code": (
            "import os\n"
            "DB_PASSWORD = os.environ.get('DB_PASSWORD')\n"
            "def connect():\n"
            "    return psycopg2.connect(password=DB_PASSWORD)\n"
        ),
    },
    {
        "name": "HardcodedSecret: JS env var (safe)",
        "language": "javascript",
        "cwe": "CWE-798",
        "vuln_type": "HARDCODED_SECRETS",
        "label": "safe",
        "source": "manual",
        "code": (
            "const SECRET_KEY = process.env.JWT_SECRET;\n"
            "function signToken(payload) {\n"
            "  return jwt.sign(payload, SECRET_KEY);\n"
            "}\n"
        ),
    },

    # ── CWE-327 Weak Cryptography ─────────────────────────────────────────────
    {
        "name": "WeakCrypto: MD5 password hash",
        "language": "python",
        "cwe": "CWE-327",
        "vuln_type": "WEAK_CRYPTOGRAPHY",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "import hashlib\n"
            "def hash_password(pwd):\n"
            "    return hashlib.md5(pwd.encode()).hexdigest()\n"
        ),
    },
    {
        "name": "WeakCrypto: SHA1 hash",
        "language": "python",
        "cwe": "CWE-327",
        "vuln_type": "WEAK_CRYPTOGRAPHY",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "import hashlib\n"
            "def hash_token(token):\n"
            "    return hashlib.sha1(token.encode()).hexdigest()\n"
        ),
    },
    {
        "name": "WeakCrypto: bcrypt (safe)",
        "language": "python",
        "cwe": "CWE-327",
        "vuln_type": "WEAK_CRYPTOGRAPHY",
        "label": "safe",
        "source": "manual",
        "code": (
            "import bcrypt\n"
            "def hash_password(pwd):\n"
            "    return bcrypt.hashpw(pwd.encode(), bcrypt.gensalt())\n"
        ),
    },
    {
        "name": "WeakCrypto: JS MD5 (vulnerable)",
        "language": "javascript",
        "cwe": "CWE-327",
        "vuln_type": "WEAK_CRYPTOGRAPHY",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "const md5 = require('md5');\n"
            "function storePassword(password) {\n"
            "  return md5(password);\n"
            "}\n"
        ),
    },

    # ── CWE-502 Insecure Deserialization ──────────────────────────────────────
    {
        "name": "Deserial: pickle.loads user data",
        "language": "python",
        "cwe": "CWE-502",
        "vuln_type": "INSECURE_DESERIALIZATION",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "import pickle\n"
            "def load_session(data):\n"
            "    return pickle.loads(data)\n"
        ),
    },
    {
        "name": "Deserial: yaml.load without Loader",
        "language": "python",
        "cwe": "CWE-502",
        "vuln_type": "INSECURE_DESERIALIZATION",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "import yaml\n"
            "def parse_config(data):\n"
            "    return yaml.load(data)\n"
        ),
    },
    {
        "name": "Deserial: yaml.safe_load (safe)",
        "language": "python",
        "cwe": "CWE-502",
        "vuln_type": "INSECURE_DESERIALIZATION",
        "label": "safe",
        "source": "manual",
        "code": (
            "import yaml\n"
            "def parse_config(data):\n"
            "    return yaml.safe_load(data)\n"
        ),
    },
    {
        "name": "Deserial: JS JSON.parse (safe)",
        "language": "javascript",
        "cwe": "CWE-502",
        "vuln_type": "INSECURE_DESERIALIZATION",
        "label": "safe",
        "source": "manual",
        "code": (
            "function parseData(body) {\n"
            "  return JSON.parse(body);\n"
            "}\n"
        ),
    },
    {
        "name": "Deserial: JS eval on JSON (vulnerable)",
        "language": "javascript",
        "cwe": "CWE-502",
        "vuln_type": "INSECURE_DESERIALIZATION",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "function parseData(body) {\n"
            "  return eval('(' + body + ')');\n"
            "}\n"
        ),
    },

    # ── CWE-918 SSRF ──────────────────────────────────────────────────────────
    {
        "name": "SSRF: requests.get with user URL",
        "language": "python",
        "cwe": "CWE-918",
        "vuln_type": "SSRF",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "import requests\n"
            "def fetch(url):\n"
            "    return requests.get(url).text\n"
        ),
    },
    {
        "name": "SSRF: fetch with user URL (JS)",
        "language": "javascript",
        "cwe": "CWE-918",
        "vuln_type": "SSRF",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "async function proxy(req, res) {\n"
            "  const url = req.query.url;\n"
            "  const data = await fetch(url);\n"
            "  res.send(await data.text());\n"
            "}\n"
        ),
    },
    {
        "name": "SSRF: allowlist check (safe)",
        "language": "python",
        "cwe": "CWE-918",
        "vuln_type": "SSRF",
        "label": "safe",
        "source": "manual",
        "code": (
            "import requests\n"
            "from urllib.parse import urlparse\n"
            "ALLOWED = {'api.example.com', 'data.example.com'}\n"
            "def fetch(url):\n"
            "    host = urlparse(url).hostname\n"
            "    if host not in ALLOWED:\n"
            "        raise ValueError('Blocked host')\n"
            "    return requests.get(url).text\n"
        ),
    },

    # ── CWE-284 IDOR ──────────────────────────────────────────────────────────
    {
        "name": "IDOR: direct object reference",
        "language": "python",
        "cwe": "CWE-284",
        "vuln_type": "IDOR",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "def get_invoice(invoice_id):\n"
            "    return db.query('SELECT * FROM invoices WHERE id = %s', (invoice_id,))\n"
        ),
    },
    {
        "name": "IDOR: ownership check (safe)",
        "language": "python",
        "cwe": "CWE-284",
        "vuln_type": "IDOR",
        "label": "safe",
        "source": "manual",
        "code": (
            "def get_invoice(invoice_id, current_user_id):\n"
            "    inv = db.query('SELECT * FROM invoices WHERE id = %s', (invoice_id,))\n"
            "    if inv and inv['user_id'] != current_user_id:\n"
            "        raise PermissionError('Access denied')\n"
            "    return inv\n"
        ),
    },
    {
        "name": "IDOR: JS no ownership check",
        "language": "javascript",
        "cwe": "CWE-284",
        "vuln_type": "IDOR",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "app.get('/api/orders/:id', async (req, res) => {\n"
            "  const order = await db.findById(req.params.id);\n"
            "  res.json(order);\n"
            "});\n"
        ),
    },

    # ── CWE-601 Open Redirect ─────────────────────────────────────────────────
    {
        "name": "OpenRedirect: Flask redirect user URL",
        "language": "python",
        "cwe": "CWE-601",
        "vuln_type": "OPEN_REDIRECT",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "from flask import request, redirect\n"
            "def login_redirect():\n"
            "    next_url = request.args.get('next')\n"
            "    return redirect(next_url)\n"
        ),
    },
    {
        "name": "OpenRedirect: JS location href",
        "language": "javascript",
        "cwe": "CWE-601",
        "vuln_type": "OPEN_REDIRECT",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "const params = new URLSearchParams(location.search);\n"
            "const next = params.get('next');\n"
            "window.location.href = next;\n"
        ),
    },
    {
        "name": "OpenRedirect: relative path check (safe)",
        "language": "python",
        "cwe": "CWE-601",
        "vuln_type": "OPEN_REDIRECT",
        "label": "safe",
        "source": "manual",
        "code": (
            "from flask import request, redirect\n"
            "from urllib.parse import urlparse\n"
            "def login_redirect():\n"
            "    next_url = request.args.get('next', '/')\n"
            "    if urlparse(next_url).netloc:\n"
            "        next_url = '/'\n"
            "    return redirect(next_url)\n"
        ),
    },

    # ── CWE-400 Log Injection ─────────────────────────────────────────────────
    {
        "name": "LogInjection: user input in log",
        "language": "python",
        "cwe": "CWE-400",
        "vuln_type": "LOG_INJECTION",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "import logging\n"
            "def login(username):\n"
            "    logging.info(f'Login attempt: {username}')\n"
        ),
    },
    {
        "name": "LogInjection: sanitized log (safe)",
        "language": "python",
        "cwe": "CWE-400",
        "vuln_type": "LOG_INJECTION",
        "label": "safe",
        "source": "manual",
        "code": (
            "import logging, re\n"
            "def login(username):\n"
            "    safe = re.sub(r'[\\r\\n]', '', username)\n"
            "    logging.info('Login attempt: %s', safe)\n"
        ),
    },

    # ── CWE-611 XXE ───────────────────────────────────────────────────────────
    {
        "name": "XXE: lxml etree unsafe parse",
        "language": "python",
        "cwe": "CWE-611",
        "vuln_type": "XXE",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "from lxml import etree\n"
            "def parse_xml(data):\n"
            "    tree = etree.fromstring(data)\n"
            "    return tree\n"
        ),
    },
    {
        "name": "XXE: defusedxml (safe)",
        "language": "python",
        "cwe": "CWE-611",
        "vuln_type": "XXE",
        "label": "safe",
        "source": "manual",
        "code": (
            "import defusedxml.ElementTree as ET\n"
            "def parse_xml(data):\n"
            "    return ET.fromstring(data)\n"
        ),
    },

    # ── CWE-89 SQLi additional edge cases ────────────────────────────────────
    {
        "name": "SQLi: % operator format",
        "language": "python",
        "cwe": "CWE-89",
        "vuln_type": "SQL_INJECTION",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "def find_user(email):\n"
            "    sql = \"SELECT * FROM users WHERE email = '%s'\" % email\n"
            "    cursor.execute(sql)\n"
        ),
    },
    {
        "name": "SQLi: JS string concat (vulnerable)",
        "language": "javascript",
        "cwe": "CWE-89",
        "vuln_type": "SQL_INJECTION",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "function findUser(email) {\n"
            "  const sql = \"SELECT * FROM users WHERE email = '\" + email + \"'\";\n"
            "  return db.query(sql);\n"
            "}\n"
        ),
    },

    # ── CWE-22 Path Traversal additional ─────────────────────────────────────
    {
        "name": "PathTraversal: JS res.sendFile user path",
        "language": "javascript",
        "cwe": "CWE-22",
        "vuln_type": "PATH_TRAVERSAL",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "app.get('/download', (req, res) => {\n"
            "  const file = req.query.file;\n"
            "  res.sendFile('/var/uploads/' + file);\n"
            "});\n"
        ),
    },

    # ── CWE-78 Cmd Injection additional ──────────────────────────────────────
    {
        "name": "CmdInjection: Python eval user input",
        "language": "python",
        "cwe": "CWE-78",
        "vuln_type": "COMMAND_INJECTION",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "def calculate(expr):\n"
            "    return eval(expr)\n"
        ),
    },

    # ── CWE-918 SSRF additional ───────────────────────────────────────────────
    {
        "name": "SSRF: httpx with user URL",
        "language": "python",
        "cwe": "CWE-918",
        "vuln_type": "SSRF",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "import httpx\n"
            "async def proxy(url):\n"
            "    async with httpx.AsyncClient() as client:\n"
            "        return await client.get(url)\n"
        ),
    },

    # ── CWE-798 Hardcoded additional ──────────────────────────────────────────
    {
        "name": "HardcodedSecret: DB connection string",
        "language": "python",
        "cwe": "CWE-798",
        "vuln_type": "HARDCODED_SECRETS",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "DATABASE_URL = 'postgresql://admin:password123@localhost/mydb'\n"
            "engine = create_engine(DATABASE_URL)\n"
        ),
    },
    {
        "name": "HardcodedSecret: JS AWS key",
        "language": "javascript",
        "cwe": "CWE-798",
        "vuln_type": "HARDCODED_SECRETS",
        "label": "vulnerable",
        "source": "manual",
        "code": (
            "const AWS = require('aws-sdk');\n"
            "AWS.config.update({\n"
            "  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',\n"
            "  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n"
            "});\n"
        ),
    },

    # =========================================================================
    # OWASP BENCHMARK SUITE — modelled after BenchmarkTest patterns
    # https://owasp.org/www-project-benchmark/
    # =========================================================================

    # ── CWE-330 Weak Randomness (OWASP BenchmarkTest00001 family) ────────────
    {
        "name": "[OWASP] WeakRandom: random.random() for token",
        "language": "python",
        "cwe": "CWE-330",
        "vuln_type": "WEAK_RANDOMNESS",
        "label": "vulnerable",
        "source": "owasp",
        "code": (
            "import random\n"
            "def generate_token():\n"
            "    return str(random.random())\n"
        ),
    },
    {
        "name": "[OWASP] WeakRandom: random.randint session id",
        "language": "python",
        "cwe": "CWE-330",
        "vuln_type": "WEAK_RANDOMNESS",
        "label": "vulnerable",
        "source": "owasp",
        "code": (
            "import random\n"
            "def make_session_id():\n"
            "    return random.randint(0, 999999)\n"
        ),
    },
    {
        "name": "[OWASP] WeakRandom: secrets.token_hex (safe)",
        "language": "python",
        "cwe": "CWE-330",
        "vuln_type": "WEAK_RANDOMNESS",
        "label": "safe",
        "source": "owasp",
        "code": (
            "import secrets\n"
            "def generate_token():\n"
            "    return secrets.token_hex(32)\n"
        ),
    },
    {
        "name": "[OWASP] WeakRandom: JS Math.random() for CSRF token",
        "language": "javascript",
        "cwe": "CWE-330",
        "vuln_type": "WEAK_RANDOMNESS",
        "label": "vulnerable",
        "source": "owasp",
        "code": (
            "function generateCSRFToken() {\n"
            "  return Math.random().toString(36).substring(2);\n"
            "}\n"
        ),
    },
    {
        "name": "[OWASP] WeakRandom: JS crypto.randomBytes (safe)",
        "language": "javascript",
        "cwe": "CWE-330",
        "vuln_type": "WEAK_RANDOMNESS",
        "label": "safe",
        "source": "owasp",
        "code": (
            "const crypto = require('crypto');\n"
            "function generateCSRFToken() {\n"
            "  return crypto.randomBytes(32).toString('hex');\n"
            "}\n"
        ),
    },

    # ── CWE-643 XPath Injection (OWASP BenchmarkTest00170 family) ────────────
    {
        "name": "[OWASP] XPathInjection: lxml string interpolation",
        "language": "python",
        "cwe": "CWE-643",
        "vuln_type": "XPATH_INJECTION",
        "label": "vulnerable",
        "source": "owasp",
        "code": (
            "from lxml import etree\n"
            "def find_user(tree, username):\n"
            "    return tree.xpath(f\"//user[name='{username}']\")\n"
        ),
    },
    {
        "name": "[OWASP] XPathInjection: JS xpath user input",
        "language": "javascript",
        "cwe": "CWE-643",
        "vuln_type": "XPATH_INJECTION",
        "label": "vulnerable",
        "source": "owasp",
        "code": (
            "const xpath = require('xpath');\n"
            "function findUser(doc, username) {\n"
            "  return xpath.select(`//user[name='${username}']`, doc);\n"
            "}\n"
        ),
    },
    {
        "name": "[OWASP] XPathInjection: parameterized variable (safe)",
        "language": "python",
        "cwe": "CWE-643",
        "vuln_type": "XPATH_INJECTION",
        "label": "safe",
        "source": "owasp",
        "code": (
            "from lxml import etree\n"
            "def find_user(tree, username):\n"
            "    return tree.xpath('//user[name=$name]', name=username)\n"
        ),
    },

    # ── CWE-90 LDAP Injection (OWASP BenchmarkTest00035 family) ──────────────
    {
        "name": "[OWASP] LDAPInjection: unsanitized filter",
        "language": "python",
        "cwe": "CWE-90",
        "vuln_type": "LDAP_INJECTION",
        "label": "vulnerable",
        "source": "owasp",
        "code": (
            "import ldap3\n"
            "def find_user(conn, username):\n"
            "    search_filter = f'(uid={username})'\n"
            "    conn.search('dc=example,dc=com', search_filter)\n"
            "    return conn.entries\n"
        ),
    },
    {
        "name": "[OWASP] LDAPInjection: escaped filter (safe)",
        "language": "python",
        "cwe": "CWE-90",
        "vuln_type": "LDAP_INJECTION",
        "label": "safe",
        "source": "owasp",
        "code": (
            "import ldap3\n"
            "from ldap3.utils.conv import escape_filter_chars\n"
            "def find_user(conn, username):\n"
            "    safe_user = escape_filter_chars(username)\n"
            "    search_filter = f'(uid={safe_user})'\n"
            "    conn.search('dc=example,dc=com', search_filter)\n"
            "    return conn.entries\n"
        ),
    },

    # ── CWE-614 Insecure Cookie (OWASP BenchmarkTest00080 family) ────────────
    {
        "name": "[OWASP] InsecureCookie: missing Secure flag",
        "language": "python",
        "cwe": "CWE-614",
        "vuln_type": "INSECURE_COOKIE",
        "label": "vulnerable",
        "source": "owasp",
        "code": (
            "from flask import make_response\n"
            "def set_session(user_id):\n"
            "    resp = make_response('OK')\n"
            "    resp.set_cookie('session', user_id)\n"
            "    return resp\n"
        ),
    },
    {
        "name": "[OWASP] InsecureCookie: missing HttpOnly flag",
        "language": "javascript",
        "cwe": "CWE-614",
        "vuln_type": "INSECURE_COOKIE",
        "label": "vulnerable",
        "source": "owasp",
        "code": (
            "res.cookie('session', token, {\n"
            "  maxAge: 86400000,\n"
            "  secure: false\n"
            "});\n"
        ),
    },
    {
        "name": "[OWASP] InsecureCookie: secure + httponly (safe)",
        "language": "python",
        "cwe": "CWE-614",
        "vuln_type": "INSECURE_COOKIE",
        "label": "safe",
        "source": "owasp",
        "code": (
            "from flask import make_response\n"
            "def set_session(user_id):\n"
            "    resp = make_response('OK')\n"
            "    resp.set_cookie('session', user_id, secure=True, httponly=True, samesite='Strict')\n"
            "    return resp\n"
        ),
    },

    # ── CWE-295 Improper Certificate Validation (OWASP) ──────────────────────
    {
        "name": "[OWASP] TLSValidation: requests verify=False",
        "language": "python",
        "cwe": "CWE-295",
        "vuln_type": "IMPROPER_TLS_VALIDATION",
        "label": "vulnerable",
        "source": "owasp",
        "code": (
            "import requests\n"
            "def fetch_data(url):\n"
            "    return requests.get(url, verify=False).json()\n"
        ),
    },
    {
        "name": "[OWASP] TLSValidation: JS rejectUnauthorized false",
        "language": "javascript",
        "cwe": "CWE-295",
        "vuln_type": "IMPROPER_TLS_VALIDATION",
        "label": "vulnerable",
        "source": "owasp",
        "code": (
            "const https = require('https');\n"
            "const agent = new https.Agent({ rejectUnauthorized: false });\n"
            "fetch('https://api.example.com/data', { agent });\n"
        ),
    },
    {
        "name": "[OWASP] TLSValidation: default verify (safe)",
        "language": "python",
        "cwe": "CWE-295",
        "vuln_type": "IMPROPER_TLS_VALIDATION",
        "label": "safe",
        "source": "owasp",
        "code": (
            "import requests\n"
            "def fetch_data(url):\n"
            "    return requests.get(url).json()\n"
        ),
    },

    # ── CWE-89 SQLi additional OWASP patterns ────────────────────────────────
    {
        "name": "[OWASP] SQLi: dynamic ORDER BY clause",
        "language": "python",
        "cwe": "CWE-89",
        "vuln_type": "SQL_INJECTION",
        "label": "vulnerable",
        "source": "owasp",
        "code": (
            "def list_users(sort_col):\n"
            "    query = f'SELECT * FROM users ORDER BY {sort_col}'\n"
            "    return db.execute(query).fetchall()\n"
        ),
    },
    {
        "name": "[OWASP] SQLi: stored procedure concat",
        "language": "python",
        "cwe": "CWE-89",
        "vuln_type": "SQL_INJECTION",
        "label": "vulnerable",
        "source": "owasp",
        "code": (
            "def search_products(keyword):\n"
            "    proc = \"EXEC SearchProducts '\" + keyword + \"'\"\n"
            "    return db.execute(proc).fetchall()\n"
        ),
    },
    {
        "name": "[OWASP] SQLi: JS knex raw unsafe",
        "language": "javascript",
        "cwe": "CWE-89",
        "vuln_type": "SQL_INJECTION",
        "label": "vulnerable",
        "source": "owasp",
        "code": (
            "async function searchUsers(name) {\n"
            "  return knex.raw(`SELECT * FROM users WHERE name = '${name}'`);\n"
            "}\n"
        ),
    },
    {
        "name": "[OWASP] SQLi: knex parameterized (safe)",
        "language": "javascript",
        "cwe": "CWE-89",
        "vuln_type": "SQL_INJECTION",
        "label": "safe",
        "source": "owasp",
        "code": (
            "async function searchUsers(name) {\n"
            "  return knex('users').where({ name });\n"
            "}\n"
        ),
    },

    # ── CWE-78 Cmd Injection additional OWASP patterns ────────────────────────
    {
        "name": "[OWASP] CmdInjection: Python popen user input",
        "language": "python",
        "cwe": "CWE-78",
        "vuln_type": "COMMAND_INJECTION",
        "label": "vulnerable",
        "source": "owasp",
        "code": (
            "import os\n"
            "def convert_image(filename):\n"
            "    os.popen(f'convert {filename} output.png')\n"
        ),
    },
    {
        "name": "[OWASP] CmdInjection: shlex.quote protected (safe)",
        "language": "python",
        "cwe": "CWE-78",
        "vuln_type": "COMMAND_INJECTION",
        "label": "safe",
        "source": "owasp",
        "code": (
            "import subprocess, shlex\n"
            "def convert_image(filename):\n"
            "    safe = shlex.quote(filename)\n"
            "    subprocess.run(f'convert {safe} output.png', shell=True)\n"
        ),
    },
    {
        "name": "[OWASP] CmdInjection: JS spawn shell=true",
        "language": "javascript",
        "cwe": "CWE-78",
        "vuln_type": "COMMAND_INJECTION",
        "label": "vulnerable",
        "source": "owasp",
        "code": (
            "const { spawn } = require('child_process');\n"
            "function compress(file) {\n"
            "  spawn('gzip ' + file, { shell: true });\n"
            "}\n"
        ),
    },

    # =========================================================================
    # JULIET TEST SUITE — modelled after NIST SARD Juliet patterns
    # https://samate.nist.gov/SARD/test-suites/112
    # =========================================================================

    # ── CWE-89 SQLi (Juliet CWE89_SQL_Injection family) ──────────────────────
    {
        "name": "[Juliet] SQLi: getParameter concat (bad)",
        "language": "python",
        "cwe": "CWE-89",
        "vuln_type": "SQL_INJECTION",
        "label": "vulnerable",
        "source": "juliet",
        "code": (
            "from flask import request\n"
            "def bad():\n"
            "    data = request.args.get('id')\n"
            "    query = 'SELECT * FROM users WHERE id=' + data\n"
            "    cursor.execute(query)\n"
        ),
    },
    {
        "name": "[Juliet] SQLi: prepared statement (good)",
        "language": "python",
        "cwe": "CWE-89",
        "vuln_type": "SQL_INJECTION",
        "label": "safe",
        "source": "juliet",
        "code": (
            "from flask import request\n"
            "def good():\n"
            "    data = request.args.get('id')\n"
            "    cursor.execute('SELECT * FROM users WHERE id = ?', (data,))\n"
        ),
    },

    # ── CWE-78 OS Command Injection (Juliet CWE78 family) ────────────────────
    {
        "name": "[Juliet] CmdInjection: Runtime.exec concat (bad)",
        "language": "python",
        "cwe": "CWE-78",
        "vuln_type": "COMMAND_INJECTION",
        "label": "vulnerable",
        "source": "juliet",
        "code": (
            "import subprocess\n"
            "from flask import request\n"
            "def bad():\n"
            "    cmd = request.args.get('cmd')\n"
            "    subprocess.call('ls ' + cmd, shell=True)\n"
        ),
    },
    {
        "name": "[Juliet] CmdInjection: fixed command (good)",
        "language": "python",
        "cwe": "CWE-78",
        "vuln_type": "COMMAND_INJECTION",
        "label": "safe",
        "source": "juliet",
        "code": (
            "import subprocess\n"
            "def good():\n"
            "    subprocess.call(['ls', '-la'], shell=False)\n"
        ),
    },

    # ── CWE-22 Path Traversal (Juliet CWE22 family) ──────────────────────────
    {
        "name": "[Juliet] PathTraversal: pathlib no validation (bad)",
        "language": "python",
        "cwe": "CWE-22",
        "vuln_type": "PATH_TRAVERSAL",
        "label": "vulnerable",
        "source": "juliet",
        "code": (
            "from pathlib import Path\n"
            "from flask import request\n"
            "def bad():\n"
            "    filename = request.args.get('file')\n"
            "    return Path('/var/data') / filename\n"
        ),
    },
    {
        "name": "[Juliet] PathTraversal: resolve + prefix check (good)",
        "language": "python",
        "cwe": "CWE-22",
        "vuln_type": "PATH_TRAVERSAL",
        "label": "safe",
        "source": "juliet",
        "code": (
            "from pathlib import Path\n"
            "BASE = Path('/var/data').resolve()\n"
            "def good(filename):\n"
            "    target = (BASE / filename).resolve()\n"
            "    if not str(target).startswith(str(BASE)):\n"
            "        raise ValueError('Path traversal detected')\n"
            "    return target.read_text()\n"
        ),
    },
    {
        "name": "[Juliet] PathTraversal: absolute path from user (bad)",
        "language": "python",
        "cwe": "CWE-22",
        "vuln_type": "PATH_TRAVERSAL",
        "label": "vulnerable",
        "source": "juliet",
        "code": (
            "import os\n"
            "from flask import request\n"
            "def bad():\n"
            "    filename = request.form['file']\n"
            "    return open(os.path.join('/uploads', filename)).read()\n"
        ),
    },

    # ── CWE-79 XSS (Juliet CWE80_XSS family) ────────────────────────────────
    {
        "name": "[Juliet] XSS: Jinja2 autoescape disabled (bad)",
        "language": "python",
        "cwe": "CWE-79",
        "vuln_type": "XSS",
        "label": "vulnerable",
        "source": "juliet",
        "code": (
            "from jinja2 import Environment\n"
            "env = Environment(autoescape=False)\n"
            "def bad(user_input):\n"
            "    tmpl = env.from_string('<p>Hello {{ name }}</p>')\n"
            "    return tmpl.render(name=user_input)\n"
        ),
    },
    {
        "name": "[Juliet] XSS: Jinja2 autoescape enabled (good)",
        "language": "python",
        "cwe": "CWE-79",
        "vuln_type": "XSS",
        "label": "safe",
        "source": "juliet",
        "code": (
            "from jinja2 import Environment\n"
            "env = Environment(autoescape=True)\n"
            "def good(user_input):\n"
            "    tmpl = env.from_string('<p>Hello {{ name }}</p>')\n"
            "    return tmpl.render(name=user_input)\n"
        ),
    },
    {
        "name": "[Juliet] XSS: React dangerouslySetInnerHTML (bad)",
        "language": "javascript",
        "cwe": "CWE-79",
        "vuln_type": "XSS",
        "label": "vulnerable",
        "source": "juliet",
        "code": (
            "function Comment({ userHtml }) {\n"
            "  return <div dangerouslySetInnerHTML={{ __html: userHtml }} />;\n"
            "}\n"
        ),
    },
    {
        "name": "[Juliet] XSS: React safe render (good)",
        "language": "javascript",
        "cwe": "CWE-79",
        "vuln_type": "XSS",
        "label": "safe",
        "source": "juliet",
        "code": (
            "function Comment({ text }) {\n"
            "  return <div>{text}</div>;\n"
            "}\n"
        ),
    },

    # ── CWE-327/328 Weak Hash without salt (Juliet) ───────────────────────────
    {
        "name": "[Juliet] WeakHash: SHA256 no salt (bad)",
        "language": "python",
        "cwe": "CWE-327",
        "vuln_type": "WEAK_CRYPTOGRAPHY",
        "label": "vulnerable",
        "source": "juliet",
        "code": (
            "import hashlib\n"
            "def store_password(password):\n"
            "    return hashlib.sha256(password.encode()).hexdigest()\n"
        ),
    },
    {
        "name": "[Juliet] WeakHash: SHA256 with salt (good)",
        "language": "python",
        "cwe": "CWE-327",
        "vuln_type": "WEAK_CRYPTOGRAPHY",
        "label": "safe",
        "source": "juliet",
        "code": (
            "import hashlib, os\n"
            "def store_password(password):\n"
            "    salt = os.urandom(32)\n"
            "    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)\n"
            "    return salt + key\n"
        ),
    },
    {
        "name": "[Juliet] WeakCrypto: DES encryption (bad)",
        "language": "python",
        "cwe": "CWE-327",
        "vuln_type": "WEAK_CRYPTOGRAPHY",
        "label": "vulnerable",
        "source": "juliet",
        "code": (
            "from Crypto.Cipher import DES\n"
            "def encrypt(data, key):\n"
            "    cipher = DES.new(key, DES.MODE_ECB)\n"
            "    return cipher.encrypt(data)\n"
        ),
    },
    {
        "name": "[Juliet] WeakCrypto: AES-GCM (good)",
        "language": "python",
        "cwe": "CWE-327",
        "vuln_type": "WEAK_CRYPTOGRAPHY",
        "label": "safe",
        "source": "juliet",
        "code": (
            "from Crypto.Cipher import AES\n"
            "from Crypto.Random import get_random_bytes\n"
            "def encrypt(data, key):\n"
            "    nonce = get_random_bytes(16)\n"
            "    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)\n"
            "    return nonce + cipher.encrypt(data)\n"
        ),
    },

    # ── CWE-502 Deserialization (Juliet) ──────────────────────────────────────
    {
        "name": "[Juliet] Deserial: marshal.loads user data (bad)",
        "language": "python",
        "cwe": "CWE-502",
        "vuln_type": "INSECURE_DESERIALIZATION",
        "label": "vulnerable",
        "source": "juliet",
        "code": (
            "import marshal\n"
            "def load_object(data):\n"
            "    return marshal.loads(data)\n"
        ),
    },
    {
        "name": "[Juliet] Deserial: JS node-serialize (bad)",
        "language": "javascript",
        "cwe": "CWE-502",
        "vuln_type": "INSECURE_DESERIALIZATION",
        "label": "vulnerable",
        "source": "juliet",
        "code": (
            "const serialize = require('node-serialize');\n"
            "function loadProfile(cookie) {\n"
            "  return serialize.unserialize(cookie);\n"
            "}\n"
        ),
    },

    # ── CWE-94 Code Injection (Juliet) ────────────────────────────────────────
    {
        "name": "[Juliet] CodeInjection: exec() user input (bad)",
        "language": "python",
        "cwe": "CWE-94",
        "vuln_type": "CODE_INJECTION",
        "label": "vulnerable",
        "source": "juliet",
        "code": (
            "from flask import request\n"
            "def bad():\n"
            "    code = request.args.get('expr')\n"
            "    exec(code)\n"
        ),
    },
    {
        "name": "[Juliet] CodeInjection: JS eval user input (bad)",
        "language": "javascript",
        "cwe": "CWE-94",
        "vuln_type": "CODE_INJECTION",
        "label": "vulnerable",
        "source": "juliet",
        "code": (
            "app.get('/calc', (req, res) => {\n"
            "  const expr = req.query.expr;\n"
            "  const result = eval(expr);\n"
            "  res.json({ result });\n"
            "});\n"
        ),
    },
    {
        "name": "[Juliet] CodeInjection: ast.literal_eval (good)",
        "language": "python",
        "cwe": "CWE-94",
        "vuln_type": "CODE_INJECTION",
        "label": "safe",
        "source": "juliet",
        "code": (
            "import ast\n"
            "from flask import request\n"
            "def good():\n"
            "    expr = request.args.get('value')\n"
            "    return ast.literal_eval(expr)\n"
        ),
    },

    # ── CWE-601 Open Redirect additional (Juliet) ─────────────────────────────
    {
        "name": "[Juliet] OpenRedirect: header Location injection (bad)",
        "language": "python",
        "cwe": "CWE-601",
        "vuln_type": "OPEN_REDIRECT",
        "label": "vulnerable",
        "source": "juliet",
        "code": (
            "from flask import request, redirect\n"
            "def bad():\n"
            "    url = request.form.get('returnUrl')\n"
            "    return redirect(url)\n"
        ),
    },
    {
        "name": "[Juliet] OpenRedirect: JS res.redirect user param (bad)",
        "language": "javascript",
        "cwe": "CWE-601",
        "vuln_type": "OPEN_REDIRECT",
        "label": "vulnerable",
        "source": "juliet",
        "code": (
            "app.get('/logout', (req, res) => {\n"
            "  const returnUrl = req.query.return;\n"
            "  res.redirect(returnUrl);\n"
            "});\n"
        ),
    },

    # ── CWE-918 SSRF additional (Juliet) ─────────────────────────────────────
    {
        "name": "[Juliet] SSRF: urllib.request user URL (bad)",
        "language": "python",
        "cwe": "CWE-918",
        "vuln_type": "SSRF",
        "label": "vulnerable",
        "source": "juliet",
        "code": (
            "import urllib.request\n"
            "from flask import request\n"
            "def bad():\n"
            "    url = request.args.get('url')\n"
            "    return urllib.request.urlopen(url).read()\n"
        ),
    },
    {
        "name": "[Juliet] SSRF: JS axios with user URL (bad)",
        "language": "javascript",
        "cwe": "CWE-918",
        "vuln_type": "SSRF",
        "label": "vulnerable",
        "source": "juliet",
        "code": (
            "const axios = require('axios');\n"
            "async function proxy(req, res) {\n"
            "  const { url } = req.body;\n"
            "  const response = await axios.get(url);\n"
            "  res.json(response.data);\n"
            "}\n"
        ),
    },

    # ── CWE-611 XXE additional (Juliet) ───────────────────────────────────────
    {
        "name": "[Juliet] XXE: minidom unsafe parse (bad)",
        "language": "python",
        "cwe": "CWE-611",
        "vuln_type": "XXE",
        "label": "vulnerable",
        "source": "juliet",
        "code": (
            "from xml.dom import minidom\n"
            "def parse(xml_data):\n"
            "    return minidom.parseString(xml_data)\n"
        ),
    },
    {
        "name": "[Juliet] XXE: expat safe parser (good)",
        "language": "python",
        "cwe": "CWE-611",
        "vuln_type": "XXE",
        "label": "safe",
        "source": "juliet",
        "code": (
            "import defusedxml.minidom as dxml\n"
            "def parse(xml_data):\n"
            "    return dxml.parseString(xml_data)\n"
        ),
    },

    # ── CWE-284 IDOR additional (Juliet) ──────────────────────────────────────
    {
        "name": "[Juliet] IDOR: JWT sub not verified against resource (bad)",
        "language": "python",
        "cwe": "CWE-284",
        "vuln_type": "IDOR",
        "label": "vulnerable",
        "source": "juliet",
        "code": (
            "def get_document(doc_id):\n"
            "    doc = db.documents.find_one({'_id': doc_id})\n"
            "    return doc\n"
        ),
    },
    {
        "name": "[Juliet] IDOR: ownership enforced (good)",
        "language": "python",
        "cwe": "CWE-284",
        "vuln_type": "IDOR",
        "label": "safe",
        "source": "juliet",
        "code": (
            "def get_document(doc_id, current_user_id):\n"
            "    doc = db.documents.find_one({'_id': doc_id, 'owner_id': current_user_id})\n"
            "    if not doc:\n"
            "        raise PermissionError('Not found or access denied')\n"
            "    return doc\n"
        ),
    },
]
