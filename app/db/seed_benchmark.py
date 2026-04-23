"""
Seed dataset: 62 labeled Python/JS test cases covering the top CWEs.
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
]
