"""
Seed dataset: ~177 labeled Python/JS test cases covering 26 CWEs.
All CWEs are actively detected by Vulcan and map to OWASP Top 10 2021.
Sources: manual (55), OWASP Benchmark (20), Juliet Test Suite / NIST SARD (28),
         CodeQL Security-python (50), CodeQL Security_javascript (24).
Removed: CWE-20 (no Vulcan rule), CWE-113 (no Vulcan rule),
         CWE-377 (no Vulcan rule), CWE-643 (no Vulcan rule).
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

    # ═══════════════════════════════════════════════════════════════════════════
    # CodeQL Security Test Cases (Python)
    # Source: github.com/github/codeql / Security-python test suite
    # ═══════════════════════════════════════════════════════════════════════════

    # ── CWE-074 Server-Side Template Injection ────────────────────────────────
    {
        "name": "[CodeQL] SSTI: Jinja2 render_template_string with user input (bad)",
        "language": "python",
        "cwe": "CWE-74",
        "vuln_type": "SERVER_SIDE_TEMPLATE_INJECTION",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "from flask import Flask, request, render_template_string\n"
            "app = Flask(__name__)\n"
            "\n"
            "@app.route('/greet')\n"
            "def greet():\n"
            "    name = request.args.get('name', '')\n"
            "    template = '<h1>Hello ' + name + '!</h1>'\n"
            "    return render_template_string(template)  # BAD: name injected into template\n"
        ),
    },
    {
        "name": "[CodeQL] SSTI: Jinja2 render_template_string safe (good)",
        "language": "python",
        "cwe": "CWE-74",
        "vuln_type": "SERVER_SIDE_TEMPLATE_INJECTION",
        "label": "safe",
        "source": "codeql",
        "code": (
            "from flask import Flask, request, render_template_string\n"
            "app = Flask(__name__)\n"
            "\n"
            "@app.route('/greet')\n"
            "def greet():\n"
            "    name = request.args.get('name', '')\n"
            "    return render_template_string('<h1>Hello {{ name }}!</h1>', name=name)  # OK\n"
        ),
    },
    {
        "name": "[CodeQL] SSTI: Jinja2 Environment from_string with tainted template (bad)",
        "language": "python",
        "cwe": "CWE-74",
        "vuln_type": "SERVER_SIDE_TEMPLATE_INJECTION",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "from jinja2 import Environment\n"
            "from flask import request\n"
            "\n"
            "def render(user_template):\n"
            "    env = Environment()\n"
            "    t = env.from_string(user_template)  # BAD: user controls template string\n"
            "    return t.render()\n"
            "\n"
            "def view():\n"
            "    tmpl = request.args.get('template', '')\n"
            "    return render(tmpl)\n"
        ),
    },
    {
        "name": "[CodeQL] SSTI: Mako template from user input (bad)",
        "language": "python",
        "cwe": "CWE-74",
        "vuln_type": "SERVER_SIDE_TEMPLATE_INJECTION",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "from mako.template import Template\n"
            "from flask import request\n"
            "\n"
            "@app.route('/render')\n"
            "def render():\n"
            "    user_tmpl = request.args.get('t', '')\n"
            "    return Template(user_tmpl).render()  # BAD: user-controlled Mako template\n"
        ),
    },

    # ── CWE-312 Cleartext Storage / Logging of Sensitive Data ─────────────────
    {
        "name": "[CodeQL] Cleartext logging: password in log message (bad)",
        "language": "python",
        "cwe": "CWE-312",
        "vuln_type": "CLEARTEXT_STORAGE",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "import logging\n"
            "from flask import request\n"
            "\n"
            "logger = logging.getLogger(__name__)\n"
            "\n"
            "@app.route('/login', methods=['POST'])\n"
            "def login():\n"
            "    password = request.form.get('password')\n"
            "    logger.info('Login attempt with password: %s', password)  # BAD\n"
            "    return authenticate(password)\n"
        ),
    },
    {
        "name": "[CodeQL] Cleartext logging: token in exception log (bad)",
        "language": "python",
        "cwe": "CWE-312",
        "vuln_type": "CLEARTEXT_STORAGE",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "import logging\n"
            "\n"
            "def call_api(token):\n"
            "    try:\n"
            "        return requests.get(API_URL, headers={'Authorization': token})\n"
            "    except Exception as e:\n"
            "        logging.error('API call failed for token %s: %s', token, e)  # BAD\n"
        ),
    },
    {
        "name": "[CodeQL] Cleartext logging: credentials masked (good)",
        "language": "python",
        "cwe": "CWE-312",
        "vuln_type": "CLEARTEXT_STORAGE",
        "label": "safe",
        "source": "codeql",
        "code": (
            "import logging\n"
            "from flask import request\n"
            "\n"
            "logger = logging.getLogger(__name__)\n"
            "\n"
            "@app.route('/login', methods=['POST'])\n"
            "def login():\n"
            "    username = request.form.get('username')\n"
            "    password = request.form.get('password')\n"
            "    logger.info('Login attempt for user: %s', username)  # OK - no password\n"
            "    return authenticate(username, password)\n"
        ),
    },
    {
        "name": "[CodeQL] Cleartext storage: writing password to file (bad)",
        "language": "python",
        "cwe": "CWE-312",
        "vuln_type": "CLEARTEXT_STORAGE",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "from flask import request\n"
            "\n"
            "@app.route('/register', methods=['POST'])\n"
            "def register():\n"
            "    password = request.form['password']\n"
            "    with open('users.txt', 'a') as f:\n"
            "        f.write(f'{request.form[\"username\"]}:{password}\\n')  # BAD\n"
        ),
    },

    # ── CWE-209 Stack Trace Exposure ──────────────────────────────────────────
    {
        "name": "[CodeQL] Stack trace exposure: traceback in HTTP response (bad)",
        "language": "python",
        "cwe": "CWE-209",
        "vuln_type": "SENSITIVE_DATA_EXPOSURE",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "import traceback\n"
            "from flask import Flask, request\n"
            "app = Flask(__name__)\n"
            "\n"
            "@app.route('/run')\n"
            "def run():\n"
            "    try:\n"
            "        result = process(request.args.get('input'))\n"
            "        return str(result)\n"
            "    except Exception:\n"
            "        return traceback.format_exc(), 500  # BAD: leaks internals\n"
        ),
    },
    {
        "name": "[CodeQL] Stack trace exposure: str(exception) in response (bad)",
        "language": "python",
        "cwe": "CWE-209",
        "vuln_type": "SENSITIVE_DATA_EXPOSURE",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "from flask import Flask, jsonify\n"
            "app = Flask(__name__)\n"
            "\n"
            "@app.errorhandler(Exception)\n"
            "def handle_error(e):\n"
            "    return jsonify({'error': str(e)}), 500  # BAD: leaks exception detail\n"
        ),
    },
    {
        "name": "[CodeQL] Stack trace exposure: generic error message (good)",
        "language": "python",
        "cwe": "CWE-209",
        "vuln_type": "SENSITIVE_DATA_EXPOSURE",
        "label": "safe",
        "source": "codeql",
        "code": (
            "import logging\n"
            "from flask import Flask, jsonify\n"
            "app = Flask(__name__)\n"
            "\n"
            "@app.errorhandler(Exception)\n"
            "def handle_error(e):\n"
            "    logging.exception('Unhandled error')\n"
            "    return jsonify({'error': 'Internal server error'}), 500  # OK\n"
        ),
    },

    # ── CWE-730 Regular Expression Denial of Service (ReDoS) ─────────────────
    {
        "name": "[CodeQL] ReDoS: catastrophic backtracking regex on user input (bad)",
        "language": "python",
        "cwe": "CWE-730",
        "vuln_type": "UNCONTROLLED_RESOURCE_CONSUMPTION",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "import re\n"
            "from flask import request\n"
            "\n"
            "@app.route('/validate')\n"
            "def validate():\n"
            "    data = request.args.get('data', '')\n"
            "    # BAD: (a+)+ is catastrophically backtracking\n"
            "    if re.match(r'^(a+)+$', data):\n"
            "        return 'valid'\n"
            "    return 'invalid'\n"
        ),
    },
    {
        "name": "[CodeQL] ReDoS: nested quantifier regex (bad)",
        "language": "python",
        "cwe": "CWE-730",
        "vuln_type": "UNCONTROLLED_RESOURCE_CONSUMPTION",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "import re\n"
            "from flask import request\n"
            "\n"
            "def check_email(email):\n"
            "    # BAD: ([a-zA-Z0-9]+.)+ has exponential backtracking\n"
            "    pattern = r'^([a-zA-Z0-9]+\\.)+[a-zA-Z]{2,}$'\n"
            "    return re.match(pattern, email) is not None\n"
            "\n"
            "@app.route('/check')\n"
            "def check():\n"
            "    return str(check_email(request.args.get('email', '')))\n"
        ),
    },
    {
        "name": "[CodeQL] ReDoS: safe linear regex (good)",
        "language": "python",
        "cwe": "CWE-730",
        "vuln_type": "UNCONTROLLED_RESOURCE_CONSUMPTION",
        "label": "safe",
        "source": "codeql",
        "code": (
            "import re\n"
            "from flask import request\n"
            "\n"
            "@app.route('/validate')\n"
            "def validate():\n"
            "    data = request.args.get('data', '')\n"
            "    if re.match(r'^[a-z0-9]{1,64}$', data):  # OK: simple character class\n"
            "        return 'valid'\n"
            "    return 'invalid'\n"
        ),
    },

    # ── CWE-943 NoSQL Injection ────────────────────────────────────────────────
    {
        "name": "[CodeQL] NoSQL injection: MongoDB find with user-controlled operator (bad)",
        "language": "python",
        "cwe": "CWE-943",
        "vuln_type": "NOSQL_INJECTION",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "from flask import Flask, request\n"
            "from pymongo import MongoClient\n"
            "\n"
            "app = Flask(__name__)\n"
            "db = MongoClient().mydb\n"
            "\n"
            "@app.route('/users')\n"
            "def get_users():\n"
            "    username = request.args.get('username')  # could be {'$gt': ''}\n"
            "    user = db.users.find_one({'username': username})  # BAD: operator injection\n"
            "    return str(user)\n"
        ),
    },
    {
        "name": "[CodeQL] NoSQL injection: MongoDB $where with user input (bad)",
        "language": "python",
        "cwe": "CWE-943",
        "vuln_type": "NOSQL_INJECTION",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "from flask import request\n"
            "from pymongo import MongoClient\n"
            "\n"
            "db = MongoClient().mydb\n"
            "\n"
            "@app.route('/search')\n"
            "def search():\n"
            "    expr = request.args.get('expr', 'true')\n"
            "    # BAD: $where executes arbitrary JavaScript\n"
            "    results = db.items.find({'$where': expr})\n"
            "    return str(list(results))\n"
        ),
    },
    {
        "name": "[CodeQL] NoSQL injection: MongoDB with cast to str (good)",
        "language": "python",
        "cwe": "CWE-943",
        "vuln_type": "NOSQL_INJECTION",
        "label": "safe",
        "source": "codeql",
        "code": (
            "from flask import request\n"
            "from pymongo import MongoClient\n"
            "\n"
            "db = MongoClient().mydb\n"
            "\n"
            "@app.route('/users')\n"
            "def get_users():\n"
            "    username = str(request.args.get('username', ''))  # cast to str prevents operator injection\n"
            "    user = db.users.find_one({'username': username})  # OK\n"
            "    return str(user)\n"
        ),
    },

    # ── CWE-326 Weak Cryptographic Key ────────────────────────────────────────
    {
        "name": "[CodeQL] Weak crypto key: RSA 512-bit key (bad)",
        "language": "python",
        "cwe": "CWE-326",
        "vuln_type": "WEAK_CRYPTOGRAPHY",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "from cryptography.hazmat.backends import default_backend\n"
            "\n"
            "private_key = rsa.generate_private_key(\n"
            "    public_exponent=65537,\n"
            "    key_size=512,  # BAD: 512 bits is far too small\n"
            "    backend=default_backend()\n"
            ")\n"
        ),
    },
    {
        "name": "[CodeQL] Weak crypto key: RSA 2048-bit key (good)",
        "language": "python",
        "cwe": "CWE-326",
        "vuln_type": "WEAK_CRYPTOGRAPHY",
        "label": "safe",
        "source": "codeql",
        "code": (
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "from cryptography.hazmat.backends import default_backend\n"
            "\n"
            "private_key = rsa.generate_private_key(\n"
            "    public_exponent=65537,\n"
            "    key_size=2048,  # OK\n"
            "    backend=default_backend()\n"
            ")\n"
        ),
    },
    {
        "name": "[CodeQL] Weak crypto key: DH parameters 512-bit (bad)",
        "language": "python",
        "cwe": "CWE-326",
        "vuln_type": "WEAK_CRYPTOGRAPHY",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "from cryptography.hazmat.primitives.asymmetric import dh\n"
            "from cryptography.hazmat.backends import default_backend\n"
            "\n"
            "parameters = dh.generate_parameters(\n"
            "    generator=2,\n"
            "    key_size=512,  # BAD: 512-bit DH is insecure\n"
            "    backend=default_backend()\n"
            ")\n"
        ),
    },

    # ── CWE-942 CORS Misconfiguration ─────────────────────────────────────────
    {
        "name": "[CodeQL] CORS misconfiguration: wildcard allow-all origins (bad)",
        "language": "python",
        "cwe": "CWE-942",
        "vuln_type": "CORS_MISCONFIGURATION",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "from flask import Flask\n"
            "from flask_cors import CORS\n"
            "\n"
            "app = Flask(__name__)\n"
            "CORS(app, origins='*')  # BAD: allows any origin to make cross-origin requests\n"
        ),
    },
    {
        "name": "[CodeQL] CORS misconfiguration: reflect origin header (bad)",
        "language": "python",
        "cwe": "CWE-942",
        "vuln_type": "CORS_MISCONFIGURATION",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "from flask import Flask, request, make_response\n"
            "app = Flask(__name__)\n"
            "\n"
            "@app.after_request\n"
            "def add_cors(response):\n"
            "    origin = request.headers.get('Origin', '')\n"
            "    response.headers['Access-Control-Allow-Origin'] = origin  # BAD: reflects any origin\n"
            "    response.headers['Access-Control-Allow-Credentials'] = 'true'\n"
            "    return response\n"
        ),
    },
    {
        "name": "[CodeQL] CORS misconfiguration: explicit allowlist (good)",
        "language": "python",
        "cwe": "CWE-942",
        "vuln_type": "CORS_MISCONFIGURATION",
        "label": "safe",
        "source": "codeql",
        "code": (
            "from flask import Flask\n"
            "from flask_cors import CORS\n"
            "\n"
            "app = Flask(__name__)\n"
            "ALLOWED_ORIGINS = ['https://app.example.com', 'https://admin.example.com']\n"
            "CORS(app, origins=ALLOWED_ORIGINS)  # OK\n"
        ),
    },

    # ── CWE-215 Flask Debug Mode Enabled ──────────────────────────────────────
    {
        "name": "[CodeQL] Flask debug mode: app.run(debug=True) (bad)",
        "language": "python",
        "cwe": "CWE-215",
        "vuln_type": "SENSITIVE_DATA_EXPOSURE",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            "\n"
            "if __name__ == '__main__':\n"
            "    app.run(debug=True)  # BAD: enables interactive debugger in production\n"
        ),
    },
    {
        "name": "[CodeQL] Flask debug mode: debug from env var (good)",
        "language": "python",
        "cwe": "CWE-215",
        "vuln_type": "SENSITIVE_DATA_EXPOSURE",
        "label": "safe",
        "source": "codeql",
        "code": (
            "import os\n"
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            "\n"
            "if __name__ == '__main__':\n"
            "    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'\n"
            "    app.run(debug=debug)  # OK\n"
        ),
    },

    # ── CWE-078 Command Injection (Python - enhanced CodeQL variants) ──────────
    {
        "name": "[CodeQL] CMDi: subprocess.Popen shell=True with user input (bad)",
        "language": "python",
        "cwe": "CWE-78",
        "vuln_type": "OS_COMMAND_INJECTION",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "import subprocess\n"
            "from flask import request\n"
            "\n"
            "@app.route('/convert')\n"
            "def convert():\n"
            "    filename = request.args.get('file', '')\n"
            "    # BAD: shell=True with user-controlled string\n"
            "    subprocess.Popen('convert ' + filename + ' out.pdf', shell=True)\n"
            "    return 'done'\n"
        ),
    },
    {
        "name": "[CodeQL] CMDi: subprocess.call with user input (bad)",
        "language": "python",
        "cwe": "CWE-78",
        "vuln_type": "OS_COMMAND_INJECTION",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "import subprocess\n"
            "from flask import request\n"
            "\n"
            "@app.route('/ping')\n"
            "def ping():\n"
            "    host = request.args.get('host', '')\n"
            "    subprocess.call('ping -c 1 ' + host, shell=True)  # BAD\n"
            "    return 'pinged'\n"
        ),
    },
    {
        "name": "[CodeQL] CMDi: subprocess.run with list args (good)",
        "language": "python",
        "cwe": "CWE-78",
        "vuln_type": "OS_COMMAND_INJECTION",
        "label": "safe",
        "source": "codeql",
        "code": (
            "import subprocess\n"
            "from flask import request\n"
            "\n"
            "@app.route('/ping')\n"
            "def ping():\n"
            "    host = request.args.get('host', '')\n"
            "    # OK: list form prevents shell injection\n"
            "    subprocess.run(['ping', '-c', '1', host], capture_output=True, timeout=5)\n"
            "    return 'pinged'\n"
        ),
    },
    {
        "name": "[CodeQL] CMDi: restricted characters sanitizer (bad - spurious alert)",
        "language": "python",
        "cwe": "CWE-78",
        "vuln_type": "OS_COMMAND_INJECTION",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "import re, os\n"
            "from flask import request\n"
            "\n"
            "@app.route('/ls')\n"
            "def list_dir():\n"
            "    path = request.args.get('path', '')\n"
            "    # Regex whitelist alone is insufficient - still uses shell=True\n"
            "    if re.match(r'^[a-zA-Z0-9/_-]+$', path):\n"
            "        os.system('ls ' + path)  # BAD: still vulnerable despite whitelist\n"
            "    return 'ok'\n"
        ),
    },

    # ── CWE-089 SQL Injection (Python - enhanced CodeQL variants) ─────────────
    {
        "name": "[CodeQL] SQLi: Django cursor.execute with % formatting (bad)",
        "language": "python",
        "cwe": "CWE-89",
        "vuln_type": "SQL_INJECTION",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "from django.db import connection\n"
            "from flask import request\n"
            "\n"
            "def get_user(username):\n"
            "    with connection.cursor() as cursor:\n"
            "        # BAD: string formatting instead of parameterized query\n"
            "        cursor.execute(\"SELECT * FROM users WHERE username = '%s'\" % username)\n"
            "        return cursor.fetchone()\n"
        ),
    },
    {
        "name": "[CodeQL] SQLi: Django ORM raw() with format string (bad)",
        "language": "python",
        "cwe": "CWE-89",
        "vuln_type": "SQL_INJECTION",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "from django.db.models import User\n"
            "from flask import request\n"
            "\n"
            "@app.route('/users/<username>')\n"
            "def show_user(username):\n"
            "    # BAD: raw() with string interpolation\n"
            "    return str(list(User.objects.raw(\n"
            "        \"SELECT * FROM users WHERE username = '%s'\" % username\n"
            "    )))\n"
        ),
    },
    {
        "name": "[CodeQL] SQLi: Django cursor.execute parameterized (good)",
        "language": "python",
        "cwe": "CWE-89",
        "vuln_type": "SQL_INJECTION",
        "label": "safe",
        "source": "codeql",
        "code": (
            "from django.db import connection\n"
            "\n"
            "def get_user(username):\n"
            "    with connection.cursor() as cursor:\n"
            "        # OK: parameterized query\n"
            "        cursor.execute('SELECT * FROM users WHERE username = %s', [username])\n"
            "        return cursor.fetchone()\n"
        ),
    },
    {
        "name": "[CodeQL] SQLi: SQLAlchemy text() with user input (bad)",
        "language": "python",
        "cwe": "CWE-89",
        "vuln_type": "SQL_INJECTION",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "from sqlalchemy import text\n"
            "from flask import request\n"
            "\n"
            "@app.route('/search')\n"
            "def search():\n"
            "    term = request.args.get('q', '')\n"
            "    # BAD: raw string passed to text()\n"
            "    result = db.session.execute(text(f\"SELECT * FROM products WHERE name LIKE '%{term}%'\"))\n"
            "    return str(result.fetchall())\n"
        ),
    },

    # ── CWE-502 Unsafe Deserialization (Python - enhanced CodeQL variants) ─────
    {
        "name": "[CodeQL] Deserialization: yaml.load without Loader (bad)",
        "language": "python",
        "cwe": "CWE-502",
        "vuln_type": "INSECURE_DESERIALIZATION",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "import yaml\n"
            "from flask import request\n"
            "\n"
            "@app.route('/load', methods=['POST'])\n"
            "def load_config():\n"
            "    payload = request.data\n"
            "    config = yaml.load(payload)  # BAD: no Loader, uses full YAML\n"
            "    return str(config)\n"
        ),
    },
    {
        "name": "[CodeQL] Deserialization: yaml.load with SafeLoader (good)",
        "language": "python",
        "cwe": "CWE-502",
        "vuln_type": "INSECURE_DESERIALIZATION",
        "label": "safe",
        "source": "codeql",
        "code": (
            "import yaml\n"
            "from flask import request\n"
            "\n"
            "@app.route('/load', methods=['POST'])\n"
            "def load_config():\n"
            "    payload = request.data\n"
            "    config = yaml.load(payload, Loader=yaml.SafeLoader)  # OK\n"
            "    return str(config)\n"
        ),
    },
    {
        "name": "[CodeQL] Deserialization: marshal.loads user input (bad)",
        "language": "python",
        "cwe": "CWE-502",
        "vuln_type": "INSECURE_DESERIALIZATION",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "import marshal\n"
            "from flask import request\n"
            "\n"
            "@app.route('/decode', methods=['POST'])\n"
            "def decode():\n"
            "    payload = request.data\n"
            "    obj = marshal.loads(payload)  # BAD: marshal can execute arbitrary code\n"
            "    return str(obj)\n"
        ),
    },
    {
        "name": "[CodeQL] Deserialization: dill.loads user input (bad)",
        "language": "python",
        "cwe": "CWE-502",
        "vuln_type": "INSECURE_DESERIALIZATION",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "import dill\n"
            "from flask import request\n"
            "\n"
            "@app.route('/run', methods=['POST'])\n"
            "def run_object():\n"
            "    payload = request.data\n"
            "    obj = dill.loads(payload)  # BAD: dill can deserialize arbitrary Python objects\n"
            "    return str(obj)\n"
        ),
    },

    # ── CWE-022 Path Traversal (Python - enhanced CodeQL variants) ────────────
    {
        "name": "[CodeQL] Path traversal: os.path.join with user filename (bad)",
        "language": "python",
        "cwe": "CWE-22",
        "vuln_type": "PATH_TRAVERSAL",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "import os\n"
            "from flask import request\n"
            "\n"
            "STATIC_DIR = '/server/static/'\n"
            "\n"
            "@app.route('/file')\n"
            "def get_file():\n"
            "    filename = request.args.get('filename', '')\n"
            "    # BAD: ../../etc/passwd bypasses STATIC_DIR\n"
            "    f = open(os.path.join(STATIC_DIR, filename))\n"
            "    return f.read()\n"
        ),
    },
    {
        "name": "[CodeQL] Path traversal: os.path.normpath + startswith check (good)",
        "language": "python",
        "cwe": "CWE-22",
        "vuln_type": "PATH_TRAVERSAL",
        "label": "safe",
        "source": "codeql",
        "code": (
            "import os\n"
            "from flask import request, abort\n"
            "\n"
            "STATIC_DIR = '/server/static/'\n"
            "\n"
            "@app.route('/file')\n"
            "def get_file():\n"
            "    filename = request.args.get('filename', '')\n"
            "    npath = os.path.normpath(os.path.join(STATIC_DIR, filename))\n"
            "    if not npath.startswith(STATIC_DIR):  # OK: validate resolved path\n"
            "        abort(403)\n"
            "    return open(npath).read()\n"
        ),
    },

    # ═══════════════════════════════════════════════════════════════════════════
    # CodeQL Security Test Cases (JavaScript)
    # Source: github.com/github/codeql / Security_javascript test suite
    # ═══════════════════════════════════════════════════════════════════════════

    # ── CWE-078 Command Injection (JavaScript) ────────────────────────────────
    {
        "name": "[CodeQL] JS CMDi: child_process.exec with query param (bad)",
        "language": "javascript",
        "cwe": "CWE-78",
        "vuln_type": "OS_COMMAND_INJECTION",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "const cp = require('child_process');\n"
            "const http = require('http');\n"
            "const url = require('url');\n"
            "\n"
            "http.createServer((req, res) => {\n"
            "  const cmd = url.parse(req.url, true).query.path;\n"
            "  cp.exec(cmd, (err, stdout) => res.end(stdout));  // BAD\n"
            "}).listen(3000);\n"
        ),
    },
    {
        "name": "[CodeQL] JS CMDi: child_process.execSync with user input (bad)",
        "language": "javascript",
        "cwe": "CWE-78",
        "vuln_type": "OS_COMMAND_INJECTION",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "const { execSync } = require('child_process');\n"
            "const express = require('express');\n"
            "const app = express();\n"
            "\n"
            "app.get('/run', (req, res) => {\n"
            "  const cmd = req.query.cmd;\n"
            "  const output = execSync(cmd).toString();  // BAD\n"
            "  res.send(output);\n"
            "});\n"
        ),
    },
    {
        "name": "[CodeQL] JS CMDi: cp.spawn with shell:true and user input (bad)",
        "language": "javascript",
        "cwe": "CWE-78",
        "vuln_type": "OS_COMMAND_INJECTION",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "const { spawn } = require('child_process');\n"
            "const express = require('express');\n"
            "const app = express();\n"
            "\n"
            "app.post('/convert', (req, res) => {\n"
            "  const file = req.body.filename;\n"
            "  // BAD: shell:true + string concatenation\n"
            "  spawn('convert ' + file + ' output.png', { shell: true });\n"
            "  res.send('converting');\n"
            "});\n"
        ),
    },
    {
        "name": "[CodeQL] JS CMDi: cp.spawn with array args (good)",
        "language": "javascript",
        "cwe": "CWE-78",
        "vuln_type": "OS_COMMAND_INJECTION",
        "label": "safe",
        "source": "codeql",
        "code": (
            "const { spawn } = require('child_process');\n"
            "const express = require('express');\n"
            "const app = express();\n"
            "\n"
            "app.post('/convert', (req, res) => {\n"
            "  const file = req.body.filename;\n"
            "  // OK: array args with no shell\n"
            "  spawn('convert', [file, 'output.png']);\n"
            "  res.send('converting');\n"
            "});\n"
        ),
    },
    {
        "name": "[CodeQL] JS CMDi: exec with string concat (bad)",
        "language": "javascript",
        "cwe": "CWE-78",
        "vuln_type": "OS_COMMAND_INJECTION",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "const cp = require('child_process');\n"
            "const express = require('express');\n"
            "const app = express();\n"
            "\n"
            "app.get('/grep', (req, res) => {\n"
            "  const term = req.query.term;\n"
            "  cp.exec('grep ' + term + ' /var/log/app.log', (err, out) => {  // BAD\n"
            "    res.send(out);\n"
            "  });\n"
            "});\n"
        ),
    },

    # ── CWE-079 DOM-Based XSS (JavaScript) ───────────────────────────────────
    {
        "name": "[CodeQL] JS DOM XSS: document.write with postMessage data (bad)",
        "language": "javascript",
        "cwe": "CWE-79",
        "vuln_type": "CROSS_SITE_SCRIPTING",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "// BAD: postMessage data written directly to DOM\n"
            "window.addEventListener('message', function(event) {\n"
            "  document.write(event.data);\n"
            "});\n"
        ),
    },
    {
        "name": "[CodeQL] JS DOM XSS: innerHTML from location.search (bad)",
        "language": "javascript",
        "cwe": "CWE-79",
        "vuln_type": "CROSS_SITE_SCRIPTING",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "// BAD: URL parameter injected into DOM\n"
            "const params = new URLSearchParams(window.location.search);\n"
            "const name = params.get('name');\n"
            "document.getElementById('greeting').innerHTML = 'Hello ' + name;\n"
        ),
    },
    {
        "name": "[CodeQL] JS DOM XSS: eval with location.hash (bad)",
        "language": "javascript",
        "cwe": "CWE-79",
        "vuln_type": "CROSS_SITE_SCRIPTING",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "// BAD: eval on user-controlled hash\n"
            "window.onhashchange = function() {\n"
            "  const code = decodeURIComponent(window.location.hash.slice(1));\n"
            "  eval(code);  // executes arbitrary JS from URL\n"
            "};\n"
        ),
    },
    {
        "name": "[CodeQL] JS DOM XSS: textContent assignment (good)",
        "language": "javascript",
        "cwe": "CWE-79",
        "vuln_type": "CROSS_SITE_SCRIPTING",
        "label": "safe",
        "source": "codeql",
        "code": (
            "// OK: textContent does not parse HTML\n"
            "const params = new URLSearchParams(window.location.search);\n"
            "const name = params.get('name');\n"
            "document.getElementById('greeting').textContent = 'Hello ' + name;\n"
        ),
    },
    {
        "name": "[CodeQL] JS DOM XSS: postMessage with origin check (good)",
        "language": "javascript",
        "cwe": "CWE-79",
        "vuln_type": "CROSS_SITE_SCRIPTING",
        "label": "safe",
        "source": "codeql",
        "code": (
            "// OK: origin validated before processing message\n"
            "window.addEventListener('message', function(event) {\n"
            "  if (event.origin !== 'https://trusted.example.com') return;\n"
            "  document.getElementById('output').textContent = event.data;\n"
            "});\n"
        ),
    },

    # ── CWE-089 SQL Injection (JavaScript) ────────────────────────────────────
    {
        "name": "[CodeQL] JS SQLi: Express + mysql string concat (bad)",
        "language": "javascript",
        "cwe": "CWE-89",
        "vuln_type": "SQL_INJECTION",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "const express = require('express');\n"
            "const mysql = require('mysql');\n"
            "const app = express();\n"
            "const db = mysql.createConnection({ host: 'localhost', user: 'root', database: 'app' });\n"
            "\n"
            "app.get('/user', (req, res) => {\n"
            "  const name = req.query.name;\n"
            "  // BAD: string concatenation into SQL\n"
            "  db.query(\"SELECT * FROM users WHERE name = '\" + name + \"'\", (err, rows) => {\n"
            "    res.json(rows);\n"
            "  });\n"
            "});\n"
        ),
    },
    {
        "name": "[CodeQL] JS SQLi: Express + mysql parameterized (good)",
        "language": "javascript",
        "cwe": "CWE-89",
        "vuln_type": "SQL_INJECTION",
        "label": "safe",
        "source": "codeql",
        "code": (
            "const express = require('express');\n"
            "const mysql = require('mysql');\n"
            "const app = express();\n"
            "const db = mysql.createConnection({ host: 'localhost', user: 'root', database: 'app' });\n"
            "\n"
            "app.get('/user', (req, res) => {\n"
            "  const name = req.query.name;\n"
            "  // OK: parameterized query\n"
            "  db.query('SELECT * FROM users WHERE name = ?', [name], (err, rows) => {\n"
            "    res.json(rows);\n"
            "  });\n"
            "});\n"
        ),
    },
    {
        "name": "[CodeQL] JS SQLi: AWS S3 SQL query with user filter (bad)",
        "language": "javascript",
        "cwe": "CWE-89",
        "vuln_type": "SQL_INJECTION",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "const { S3Client, SelectObjectContentCommand } = require('@aws-sdk/client-s3');\n"
            "const express = require('express');\n"
            "const app = express();\n"
            "\n"
            "app.post('/query', async (req, res) => {\n"
            "  const filter = req.body.filter;  // user input\n"
            "  const client = new S3Client({ region: 'us-east-1' });\n"
            "  const params = {\n"
            "    Bucket: 'my-bucket', Key: 'data.csv',\n"
            "    ExpressionType: 'SQL',\n"
            "    Expression: 'SELECT * FROM S3Object WHERE ' + filter,  // BAD\n"
            "  };\n"
            "  await client.send(new SelectObjectContentCommand(params));\n"
            "  res.end();\n"
            "});\n"
        ),
    },

    # ── CWE-915 Prototype Pollution (JavaScript) ──────────────────────────────
    {
        "name": "[CodeQL] JS Prototype Pollution: merge with req.body (bad)",
        "language": "javascript",
        "cwe": "CWE-915",
        "vuln_type": "PROTOTYPE_POLLUTION",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "const express = require('express');\n"
            "const app = express();\n"
            "app.use(express.json());\n"
            "\n"
            "function merge(target, source) {\n"
            "  for (const key in source) {\n"
            "    if (typeof source[key] === 'object') {\n"
            "      target[key] = {};\n"
            "      merge(target[key], source[key]);  // BAD: no __proto__ check\n"
            "    } else {\n"
            "      target[key] = source[key];\n"
            "    }\n"
            "  }\n"
            "}\n"
            "\n"
            "app.post('/config', (req, res) => {\n"
            "  const cfg = {};\n"
            "  merge(cfg, req.body);  // attacker sends {\"__proto__\": {\"admin\": true}}\n"
            "  res.json(cfg);\n"
            "});\n"
        ),
    },
    {
        "name": "[CodeQL] JS Prototype Pollution: Object.assign from user input (bad)",
        "language": "javascript",
        "cwe": "CWE-915",
        "vuln_type": "PROTOTYPE_POLLUTION",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "const express = require('express');\n"
            "const app = express();\n"
            "app.use(express.json());\n"
            "\n"
            "let globalConfig = { debug: false, adminEnabled: false };\n"
            "\n"
            "app.post('/update-config', (req, res) => {\n"
            "  // BAD: Object.assign from user input can overwrite prototype\n"
            "  Object.assign(globalConfig, req.body);\n"
            "  res.json({ ok: true });\n"
            "});\n"
        ),
    },
    {
        "name": "[CodeQL] JS Prototype Pollution: hasOwnProperty check (good)",
        "language": "javascript",
        "cwe": "CWE-915",
        "vuln_type": "PROTOTYPE_POLLUTION",
        "label": "safe",
        "source": "codeql",
        "code": (
            "function safeMerge(target, source) {\n"
            "  for (const key of Object.keys(source)) {  // Object.keys skips prototype chain\n"
            "    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;\n"
            "    if (typeof source[key] === 'object' && source[key] !== null) {\n"
            "      target[key] = {};\n"
            "      safeMerge(target[key], source[key]);\n"
            "    } else {\n"
            "      target[key] = source[key];\n"
            "    }\n"
            "  }\n"
            "}\n"
        ),
    },

    # ── CWE-730 ReDoS (JavaScript) ─────────────────────────────────────────────
    {
        "name": "[CodeQL] JS ReDoS: catastrophic backtracking on user input (bad)",
        "language": "javascript",
        "cwe": "CWE-730",
        "vuln_type": "UNCONTROLLED_RESOURCE_CONSUMPTION",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "const express = require('express');\n"
            "const app = express();\n"
            "\n"
            "app.get('/validate', (req, res) => {\n"
            "  const input = req.query.input;\n"
            "  // BAD: (a+)+ has catastrophic backtracking on 'aaa...aX'\n"
            "  const valid = /^(a+)+$/.test(input);\n"
            "  res.json({ valid });\n"
            "});\n"
        ),
    },
    {
        "name": "[CodeQL] JS ReDoS: nested quantifier email regex (bad)",
        "language": "javascript",
        "cwe": "CWE-730",
        "vuln_type": "UNCONTROLLED_RESOURCE_CONSUMPTION",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "const express = require('express');\n"
            "const app = express();\n"
            "\n"
            "app.post('/register', (req, res) => {\n"
            "  const email = req.body.email;\n"
            "  // BAD: exponential backtracking on invalid emails\n"
            "  if (/^([a-zA-Z0-9]+\\.)+[a-zA-Z]{2,}$/.test(email)) {\n"
            "    res.json({ valid: true });\n"
            "  } else {\n"
            "    res.status(400).json({ error: 'Invalid email' });\n"
            "  }\n"
            "});\n"
        ),
    },
    {
        "name": "[CodeQL] JS ReDoS: simple safe regex (good)",
        "language": "javascript",
        "cwe": "CWE-730",
        "vuln_type": "UNCONTROLLED_RESOURCE_CONSUMPTION",
        "label": "safe",
        "source": "codeql",
        "code": (
            "const express = require('express');\n"
            "const app = express();\n"
            "\n"
            "app.get('/validate', (req, res) => {\n"
            "  const input = req.query.input;\n"
            "  // OK: no nested quantifiers, linear backtracking\n"
            "  const valid = /^[a-z0-9]{1,64}$/.test(input);\n"
            "  res.json({ valid });\n"
            "});\n"
        ),
    },

    # ── CWE-601 Open Redirect (JavaScript) ────────────────────────────────────
    {
        "name": "[CodeQL] JS Open Redirect: res.redirect with user URL (bad)",
        "language": "javascript",
        "cwe": "CWE-601",
        "vuln_type": "OPEN_REDIRECT",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "const express = require('express');\n"
            "const app = express();\n"
            "\n"
            "app.get('/redirect', (req, res) => {\n"
            "  const url = req.query.url;\n"
            "  res.redirect(url);  // BAD: user controls redirect target\n"
            "});\n"
        ),
    },
    {
        "name": "[CodeQL] JS Open Redirect: allowlist check (good)",
        "language": "javascript",
        "cwe": "CWE-601",
        "vuln_type": "OPEN_REDIRECT",
        "label": "safe",
        "source": "codeql",
        "code": (
            "const express = require('express');\n"
            "const app = express();\n"
            "\n"
            "const ALLOWED = new Set(['https://app.example.com', 'https://docs.example.com']);\n"
            "\n"
            "app.get('/redirect', (req, res) => {\n"
            "  const url = req.query.url;\n"
            "  if (ALLOWED.has(url)) {\n"
            "    res.redirect(url);  // OK: validated against allowlist\n"
            "  } else {\n"
            "    res.redirect('/');\n"
            "  }\n"
            "});\n"
        ),
    },

    # ── CWE-022 Path Traversal (JavaScript) ───────────────────────────────────
    {
        "name": "[CodeQL] JS Path traversal: path.join with user param (bad)",
        "language": "javascript",
        "cwe": "CWE-22",
        "vuln_type": "PATH_TRAVERSAL",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "const express = require('express');\n"
            "const path = require('path');\n"
            "const fs = require('fs');\n"
            "const app = express();\n"
            "\n"
            "app.get('/file', (req, res) => {\n"
            "  const filename = req.query.name;\n"
            "  // BAD: ../../etc/passwd escapes the static dir\n"
            "  const filePath = path.join(__dirname, 'static', filename);\n"
            "  res.sendFile(filePath);\n"
            "});\n"
        ),
    },
    {
        "name": "[CodeQL] JS Path traversal: path.normalize + startsWith (good)",
        "language": "javascript",
        "cwe": "CWE-22",
        "vuln_type": "PATH_TRAVERSAL",
        "label": "safe",
        "source": "codeql",
        "code": (
            "const express = require('express');\n"
            "const path = require('path');\n"
            "const fs = require('fs');\n"
            "const app = express();\n"
            "\n"
            "const STATIC_DIR = path.join(__dirname, 'static');\n"
            "\n"
            "app.get('/file', (req, res) => {\n"
            "  const filename = req.query.name;\n"
            "  const filePath = path.normalize(path.join(STATIC_DIR, filename));\n"
            "  if (!filePath.startsWith(STATIC_DIR)) {  // OK: validate resolved path\n"
            "    return res.status(403).send('Forbidden');\n"
            "  }\n"
            "  res.sendFile(filePath);\n"
            "});\n"
        ),
    },

    # ── CWE-614 Insecure Cookie (JavaScript) ──────────────────────────────────
    {
        "name": "[CodeQL] JS Insecure cookie: no Secure or HttpOnly flag (bad)",
        "language": "javascript",
        "cwe": "CWE-614",
        "vuln_type": "INSECURE_COOKIE",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "const express = require('express');\n"
            "const app = express();\n"
            "\n"
            "app.post('/login', (req, res) => {\n"
            "  const token = generateToken(req.body.username);\n"
            "  // BAD: missing Secure and HttpOnly flags\n"
            "  res.cookie('session', token);\n"
            "  res.json({ ok: true });\n"
            "});\n"
        ),
    },
    {
        "name": "[CodeQL] JS Insecure cookie: Secure + HttpOnly + SameSite (good)",
        "language": "javascript",
        "cwe": "CWE-614",
        "vuln_type": "INSECURE_COOKIE",
        "label": "safe",
        "source": "codeql",
        "code": (
            "const express = require('express');\n"
            "const app = express();\n"
            "\n"
            "app.post('/login', (req, res) => {\n"
            "  const token = generateToken(req.body.username);\n"
            "  // OK: all security flags set\n"
            "  res.cookie('session', token, {\n"
            "    httpOnly: true,\n"
            "    secure: true,\n"
            "    sameSite: 'Strict',\n"
            "    maxAge: 3600000,\n"
            "  });\n"
            "  res.json({ ok: true });\n"
            "});\n"
        ),
    },

    # ── CWE-798 Hardcoded Secrets (JavaScript) ────────────────────────────────
    {
        "name": "[CodeQL] JS Hardcoded secret: API key in source (bad)",
        "language": "javascript",
        "cwe": "CWE-798",
        "vuln_type": "HARDCODED_SECRET",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "const stripe = require('stripe');\n"
            "\n"
            "// BAD: hardcoded secret key committed to source control\n"
            "const stripeClient = stripe('sk_live_4xKdM9qLpR7nT2vW8yZcX3bN');\n"
            "\n"
            "async function chargeCard(amount, token) {\n"
            "  return stripeClient.charges.create({ amount, currency: 'usd', source: token });\n"
            "}\n"
        ),
    },
    {
        "name": "[CodeQL] JS Hardcoded secret: API key from env var (good)",
        "language": "javascript",
        "cwe": "CWE-798",
        "vuln_type": "HARDCODED_SECRET",
        "label": "safe",
        "source": "codeql",
        "code": (
            "const stripe = require('stripe');\n"
            "\n"
            "// OK: key loaded from environment variable\n"
            "const stripeClient = stripe(process.env.STRIPE_SECRET_KEY);\n"
            "\n"
            "async function chargeCard(amount, token) {\n"
            "  return stripeClient.charges.create({ amount, currency: 'usd', source: token });\n"
            "}\n"
        ),
    },

    # ── CWE-918 SSRF (JavaScript) ─────────────────────────────────────────────
    {
        "name": "[CodeQL] JS SSRF: fetch with user-supplied URL (bad)",
        "language": "javascript",
        "cwe": "CWE-918",
        "vuln_type": "SERVER_SIDE_REQUEST_FORGERY",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "const express = require('express');\n"
            "const fetch = require('node-fetch');\n"
            "const app = express();\n"
            "\n"
            "app.get('/proxy', async (req, res) => {\n"
            "  const url = req.query.url;\n"
            "  // BAD: attacker can request internal services (http://169.254.169.254/...)\n"
            "  const response = await fetch(url);\n"
            "  const data = await response.text();\n"
            "  res.send(data);\n"
            "});\n"
        ),
    },
    {
        "name": "[CodeQL] JS SSRF: axios with user URL (bad)",
        "language": "javascript",
        "cwe": "CWE-918",
        "vuln_type": "SERVER_SIDE_REQUEST_FORGERY",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "const express = require('express');\n"
            "const axios = require('axios');\n"
            "const app = express();\n"
            "\n"
            "app.post('/webhook-test', async (req, res) => {\n"
            "  const webhookUrl = req.body.url;\n"
            "  // BAD: internal network reachable via webhookUrl\n"
            "  const result = await axios.post(webhookUrl, { test: true });\n"
            "  res.json(result.data);\n"
            "});\n"
        ),
    },
    {
        "name": "[CodeQL] JS SSRF: domain allowlist check (good)",
        "language": "javascript",
        "cwe": "CWE-918",
        "vuln_type": "SERVER_SIDE_REQUEST_FORGERY",
        "label": "safe",
        "source": "codeql",
        "code": (
            "const express = require('express');\n"
            "const fetch = require('node-fetch');\n"
            "const { URL } = require('url');\n"
            "const app = express();\n"
            "\n"
            "const ALLOWED_HOSTS = new Set(['api.example.com', 'hooks.example.com']);\n"
            "\n"
            "app.get('/proxy', async (req, res) => {\n"
            "  const url = req.query.url;\n"
            "  const parsed = new URL(url);\n"
            "  if (!ALLOWED_HOSTS.has(parsed.hostname)) {  // OK: hostname allowlist\n"
            "    return res.status(403).send('Forbidden host');\n"
            "  }\n"
            "  const response = await fetch(url);\n"
            "  res.send(await response.text());\n"
            "});\n"
        ),
    },

    # ── CWE-327 Biased/Weak Random (JavaScript) ───────────────────────────────
    {
        "name": "[CodeQL] JS Weak random: Math.random() for security token (bad)",
        "language": "javascript",
        "cwe": "CWE-327",
        "vuln_type": "INSECURE_RANDOMNESS",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "// BAD: Math.random() is not cryptographically secure\n"
            "function generateToken() {\n"
            "  return Math.random().toString(36).substring(2, 15);\n"
            "}\n"
            "\n"
            "function generateSessionId() {\n"
            "  return Math.floor(Math.random() * 1e15).toString(16);  // BAD\n"
            "}\n"
        ),
    },
    {
        "name": "[CodeQL] JS Weak random: crypto.randomBytes() (good)",
        "language": "javascript",
        "cwe": "CWE-327",
        "vuln_type": "INSECURE_RANDOMNESS",
        "label": "safe",
        "source": "codeql",
        "code": (
            "const crypto = require('crypto');\n"
            "\n"
            "// OK: cryptographically secure random bytes\n"
            "function generateToken() {\n"
            "  return crypto.randomBytes(32).toString('hex');\n"
            "}\n"
            "\n"
            "function generateSessionId() {\n"
            "  return crypto.randomUUID();\n"
            "}\n"
        ),
    },
    {
        "name": "[CodeQL] JS Weak random: biased crypto.randomBytes modulo (bad)",
        "language": "javascript",
        "cwe": "CWE-327",
        "vuln_type": "INSECURE_RANDOMNESS",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "const crypto = require('crypto');\n"
            "\n"
            "function randomDigit() {\n"
            "  // BAD: modulo introduces bias when 256 is not divisible by 100\n"
            "  return crypto.randomBytes(1)[0] % 100;\n"
            "}\n"
            "\n"
            "function randomIndex(n) {\n"
            "  // BAD: addition of two random bytes is not uniform over their sum range\n"
            "  return (crypto.randomBytes(1)[0] + crypto.randomBytes(1)[0]) % n;\n"
            "}\n"
        ),
    },

    # ── CWE-611 XXE (JavaScript - enhanced) ───────────────────────────────────
    {
        "name": "[CodeQL] JS XXE: libxmljs parse with external entities (bad)",
        "language": "javascript",
        "cwe": "CWE-611",
        "vuln_type": "XML_EXTERNAL_ENTITY",
        "label": "vulnerable",
        "source": "codeql",
        "code": (
            "const libxmljs = require('libxmljs');\n"
            "const express = require('express');\n"
            "const app = express();\n"
            "\n"
            "app.post('/parse', (req, res) => {\n"
            "  const xml = req.body.xml;\n"
            "  // BAD: noent: true enables external entity processing\n"
            "  const doc = libxmljs.parseXml(xml, { noent: true });\n"
            "  res.send(doc.toString());\n"
            "});\n"
        ),
    },
    {
        "name": "[CodeQL] JS XXE: libxmljs parse without external entities (good)",
        "language": "javascript",
        "cwe": "CWE-611",
        "vuln_type": "XML_EXTERNAL_ENTITY",
        "label": "safe",
        "source": "codeql",
        "code": (
            "const libxmljs = require('libxmljs');\n"
            "const express = require('express');\n"
            "const app = express();\n"
            "\n"
            "app.post('/parse', (req, res) => {\n"
            "  const xml = req.body.xml;\n"
            "  // OK: noent defaults to false\n"
            "  const doc = libxmljs.parseXml(xml);\n"
            "  res.send(doc.toString());\n"
            "});\n"
        ),
    },
]
