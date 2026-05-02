from __future__ import annotations

from typing import Optional

# ── Few-shot examples ─────────────────────────────────────────────────────────
_FEW_SHOT = """\
EXAMPLE — SQL Injection fix (Python):
Vulnerable:
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)
Fixed diff:
--- a/app.py
+++ b/app.py
@@ -1,2 +1,2 @@
-    query = "SELECT * FROM users WHERE name = '" + username + "'"
-    cursor.execute(query)
+    query = "SELECT * FROM users WHERE name = ?"
+    cursor.execute(query, (username,))

EXAMPLE — Command Injection fix (Python):
Vulnerable:
    os.system("ping " + user_input)
Fixed diff:
--- a/utils.py
+++ b/utils.py
@@ -1,1 +1,1 @@
-    os.system("ping " + user_input)
+    subprocess.run(["ping", user_input], shell=False, check=True)
"""

# ── Remediation rules for all 59 detected vulnerability types ────────────────
_RULES: dict[str, dict[str, str]] = {

    # ── OWASP A03 Injection ───────────────────────────────────────────────────
    "sqli": {
        "python": (
            "Replace string-formatted SQL with cursor.execute(sql, params) using "
            "'?' or '%s' placeholders. Never build SQL strings from user input."
        ),
        "javascript": (
            "Use parameterized queries or a query builder (knex/sequelize/prisma). "
            "Never concatenate or template user input into SQL strings."
        ),
    },
    "sqlinjection": {
        "python": "Use cursor.execute(sql, (param,)) with placeholders. Never build SQL from user input.",
        "javascript": "Use parameterized queries. Never concatenate user input into SQL.",
    },
    "xss": {
        "python": (
            "Escape all user-supplied output (html.escape). Use auto-escaping templating "
            "(Jinja2 autoescape=True). Never pass raw user input to render_template_string."
        ),
        "javascript": (
            "Use textContent instead of innerHTML for untrusted data. "
            "If HTML is required sanitize with DOMPurify. Avoid document.write."
        ),
    },
    "crosssitescripting": {
        "python": "Use html.escape() on all user input before rendering. Enable Jinja2 autoescape.",
        "javascript": "Use textContent, not innerHTML. Sanitize with DOMPurify if HTML is needed.",
    },
    "commandinjection": {
        "python": (
            "Replace os.system/subprocess with shell=True with "
            "subprocess.run([cmd, arg1, arg2], shell=False). Validate inputs against an allowlist."
        ),
        "javascript": (
            "Replace child_process.exec string with execFile or spawn using "
            "an argument array. Validate and allowlist all user-supplied arguments."
        ),
    },
    "oscommandinjection": {
        "python": "Use subprocess.run([cmd, user_input], shell=False). Never use os.system or shell=True.",
        "javascript": "Use execFile(cmd, [args]) instead of exec(cmd + userInput). Validate all inputs.",
    },
    "codeinjection": {
        "python": (
            "Remove eval/exec calls. Replace with ast.literal_eval for data, "
            "a look-up table for dispatch. Never evaluate user-supplied strings as code."
        ),
        "javascript": (
            "Remove eval/Function constructor calls. Use JSON.parse for data "
            "and explicit function maps. Never execute user-supplied strings as code."
        ),
    },
    "evalcodeinjection": {
        "python": "Remove eval(). Use ast.literal_eval() or a safe dispatch dict.",
        "javascript": "Remove eval() and new Function(). Use JSON.parse() or a lookup table.",
    },
    "templateinjection": {
        "python": (
            "Never pass user input to render_template_string(). Use render_template() with "
            "a fixed template file. Enable Jinja2 autoescape=True. Validate all template variables."
        ),
        "javascript": (
            "Never interpolate user input directly into template strings used with "
            "template engines. Use a fixed template with safe context variables."
        ),
    },
    "ldapinjection": {
        "python": "Escape all user input with ldap3.utils.conv.escape_filter_chars() before building LDAP filters.",
        "javascript": "Escape special LDAP characters in user input using ldap-escape before building filter strings.",
    },
    "nosqlinjection": {
        "python": (
            "Validate query inputs as primitive types; reject dict/list from users. "
            "Use schema validation (pydantic/marshmallow). Remove $where/$expr operators."
        ),
        "javascript": (
            "Sanitize user input with mongo-sanitize or express-mongo-sanitize. "
            "Never pass raw req.body as a MongoDB query object."
        ),
    },
    "graphqlinjection": {
        "python": "Use GraphQL variables instead of string interpolation in queries. Validate all inputs.",
        "javascript": "Use parameterized GraphQL variables. Never interpolate user input into query strings.",
    },
    "xmlinjection": {
        "python": "Use defusedxml instead of xml.etree.ElementTree. Disable external entities and DTD loading.",
        "javascript": "Use a safe XML parser with external entities disabled. Set resolve_entities: false.",
    },
    "xxe": {
        "python": "Replace xml.etree.ElementTree with defusedxml.ElementTree. Set resolve_entities=False.",
        "javascript": "Disable external entity resolution. Set resolve_entities: false or use safe-xml.",
    },
    "loginjection": {
        "python": "Sanitize user input before logging: strip newlines, escape special chars, use repr() or str().",
        "javascript": "Sanitize log messages: remove CRLF, escape special characters before logger calls.",
    },
    "sensitivelogging": {
        "python": "Remove sensitive fields (password, token, secret) from log statements. Mask with '***'.",
        "javascript": "Remove sensitive data from console.log/logger calls. Never log passwords or tokens.",
    },
    "sensitizedataexposure": {
        "python": "Remove sensitive values from API responses and logs. Use environment variables for secrets.",
        "javascript": "Delete sensitive fields before returning JSON. Never log or return passwords/tokens.",
    },
    "sensitiveloggingdata": {
        "python": "Remove sensitive values from log calls. Replace with masked versions or remove entirely.",
        "javascript": "Never log req.body directly. Filter out password, token, secret fields.",
    },

    # ── OWASP A01 Broken Access Control ──────────────────────────────────────
    "pathtraversal": {
        "python": (
            "Resolve the path with os.path.abspath and verify it starts with "
            "the allowed base directory. Reject any path containing '..'."
        ),
        "javascript": (
            "Use path.resolve to canonicalize and check the result starts with "
            "the allowed base directory. Reject '..' traversal sequences."
        ),
    },
    "directorytransversal": {
        "python": "Use os.path.abspath() and check the resolved path starts with the allowed base dir.",
        "javascript": "Use path.resolve() and validate the result is within the allowed directory.",
    },
    "brokenaccess": {
        "python": "Add ownership check: verify current_user.id == resource.user_id before access.",
        "javascript": "Add authorization check: verify req.user.id === resource.userId before returning data.",
    },
    "idor": {
        "python": "Verify the authenticated user owns or is authorized for the requested resource before returning it.",
        "javascript": "Check req.user.id === resource.userId or equivalent ownership check before access.",
    },
    "massassignment": {
        "python": (
            "Use an explicit allow-list of fields when constructing model objects. "
            "Never pass **request.json or **form.data directly to model constructors."
        ),
        "javascript": (
            "Use a pick/whitelist helper to extract only allowed fields from req.body "
            "before passing to ORM/model constructors."
        ),
    },
    "unvalidatedredirect": {
        "python": "Validate redirect targets against an explicit allowlist of safe URLs/paths. Reject others.",
        "javascript": "Validate redirect destination against a whitelist. Use urlparse to check netloc.",
    },
    "openredirect": {
        "python": "Check redirect URL against allowed hosts allowlist using urlparse(url).netloc.",
        "javascript": "Validate redirect URL starts with '/' or matches allowed domains.",
    },
    "zipslip": {
        "python": (
            "After extracting each entry, resolve the full path and verify it starts "
            "with the target directory: assert resolved.startswith(target_dir)."
        ),
        "javascript": (
            "Check each zip entry path: resolve it and ensure it starts with the "
            "target extraction directory. Reject entries with '..' in the path."
        ),
    },
    "adminroute": {
        "python": "Add @login_required and role check: if not current_user.is_admin: abort(403).",
        "javascript": "Add authentication middleware and role check: if (!req.user?.isAdmin) return res.status(403).",
    },

    # ── OWASP A02 Cryptographic Failures ─────────────────────────────────────
    "sensitivedataexposure": {
        "python": "Remove sensitive values from responses and logs. Use os.environ/os.getenv for credentials.",
        "javascript": "Delete sensitive fields (password, token, secret) from response objects.",
    },
    "weakcipher": {
        "python": "Replace MD5/SHA1/DES/RC4 with hashlib.sha256 or hashlib.sha512. Use bcrypt/argon2 for passwords.",
        "javascript": "Replace MD5/SHA1 with crypto.createHash('sha256'). Use bcrypt for passwords.",
    },
    "weakcrypto": {
        "python": "Replace hashlib.md5/sha1 with hashlib.sha256 or higher. Use bcrypt for password hashing.",
        "javascript": "Replace crypto.createHash('md5'/'sha1') with 'sha256'. Use bcrypt for passwords.",
    },
    "hardcodediv": {
        "python": "Replace static IV with os.urandom(16). Generate a fresh random IV for each encryption.",
        "javascript": "Replace static IV with crypto.randomBytes(16). Generate a fresh IV per encryption.",
    },
    "useofhardcodediv": {
        "python": "Use os.urandom(16) to generate a random IV for each encryption operation.",
        "javascript": "Use crypto.randomBytes(16) to generate a fresh IV for each encryption.",
    },
    "insecurerandom": {
        "python": "Replace random.random()/random.randint() with secrets.token_bytes() or secrets.token_hex().",
        "javascript": "Replace Math.random() with crypto.randomBytes() for security-sensitive values.",
    },
    "insufficiententropy": {
        "python": "Use secrets module (secrets.token_urlsafe(32)) for tokens, sessions, and keys.",
        "javascript": "Use crypto.randomBytes(32) or crypto.randomUUID() for security-sensitive values.",
    },
    "timingattrack": {
        "python": "Replace == comparison with hmac.compare_digest(expected, actual) to prevent timing attacks.",
        "javascript": "Use crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)) for constant-time comparison.",
    },
    "timingattrackk": {
        "python": "Use hmac.compare_digest() for secret/token comparison to prevent timing side-channels.",
        "javascript": "Use crypto.timingSafeEqual() for constant-time comparison of secrets.",
    },
    "cleartexttransmission": {
        "python": "Change http:// to https:// in all URLs. Enforce TLS for sensitive data transmission.",
        "javascript": "Change http:// to https:// in all URLs. Never send credentials over plain HTTP.",
    },
    "disabledcertificatevalidation": {
        "python": "Remove verify=False from requests.get/post calls. Always use verify=True (default).",
        "javascript": "Remove rejectUnauthorized: false from https.request options. Always validate TLS certificates.",
    },
    "passwordinurl": {
        "python": "Move password/credentials from URL query params to request body or headers.",
        "javascript": "Move password from URL query params to request body (POST) or Authorization header.",
    },

    # ── OWASP A04 Insecure Design ─────────────────────────────────────────────
    "insecuredeserialization": {
        "python": (
            "Replace pickle.loads/yaml.unsafe_load with json.loads or yaml.safe_load. "
            "Never deserialize untrusted data with pickle. Validate structure after deserialization."
        ),
        "javascript": (
            "Replace unsafe deserializers with JSON.parse plus schema validation. "
            "Never deserialize untrusted data with node-serialize or serialize-javascript."
        ),
    },
    "unrestricted fileupload": {
        "python": "Validate file extension against an allowlist. Check MIME type from file magic bytes. Store outside web root.",
        "javascript": "Validate extension and MIME type (file-type library). Store with UUID filename outside web root.",
    },
    "unrestrictedfileupload": {
        "python": "Validate file extension and MIME type. Use secure_filename(). Store uploads outside web root.",
        "javascript": "Validate extension with an allowlist. Check actual MIME type from bytes. Use UUID for filename.",
    },
    "regexdos": {
        "python": (
            "Replace user-controlled regex with a fixed pattern or validate/limit input length before "
            "compiling regex. Use re.compile with timeout or validate against an allowlist."
        ),
        "javascript": (
            "Replace user-controlled regex with a fixed pattern. Use validator.js or "
            "limit input length. Avoid catastrophic backtracking patterns (nested quantifiers)."
        ),
    },
    "missingratelimiting": {
        "python": "Add Flask-Limiter or similar: @limiter.limit('5 per minute') to authentication endpoints.",
        "javascript": "Add express-rate-limit: const limiter = rateLimit({windowMs: 60000, max: 5}) to auth routes.",
    },
    "raceconditiontoctou": {
        "python": "Replace os.path.exists + open pattern with a single open() in try/except. Use file locking with fcntl.flock().",
        "javascript": "Replace fs.exists + fs.readFile with a single fs.readFile in try/catch to avoid TOCTOU.",
    },

    # ── OWASP A05 Security Misconfiguration ──────────────────────────────────
    "debugmode": {
        "python": "Set DEBUG = False or use os.getenv('DEBUG', 'False'). Never enable DEBUG in production.",
        "javascript": "Set debug: false. Use NODE_ENV === 'production' check. Remove debug middleware in production.",
    },
    "debugmodeenabled": {
        "python": "Change DEBUG = True to DEBUG = False or load from environment: DEBUG = os.getenv('DEBUG') == 'true'.",
        "javascript": "Remove debug: true. Use process.env.NODE_ENV !== 'development' check.",
    },
    "corsmisconfiguration": {
        "python": "Replace '*' with specific allowed origins: CORS(app, origins=['https://yourdomain.com']).",
        "javascript": "Replace origin: '*' with a specific domain or a function that validates against an allowlist.",
    },
    "insecurecookie": {
        "python": "Add secure=True, httponly=True, samesite='Strict' to all set_cookie calls.",
        "javascript": "Add secure: true, httpOnly: true, sameSite: 'Strict' to all cookie options.",
    },
    "insecurecookieflag": {
        "python": "Set cookie flags: response.set_cookie(key, value, secure=True, httponly=True, samesite='Lax').",
        "javascript": "Set cookie options: { secure: true, httpOnly: true, sameSite: 'Lax' }.",
    },
    "clickjacking": {
        "python": "Add X-Frame-Options header: response.headers['X-Frame-Options'] = 'DENY' or 'SAMEORIGIN'.",
        "javascript": "Add X-Frame-Options header in middleware: res.setHeader('X-Frame-Options', 'DENY').",
    },
    "informationexposure": {
        "python": "Remove stack traces and debug info from error responses. Return generic error messages to users.",
        "javascript": "Remove err.stack from error responses. Return a generic message, log details server-side.",
    },

    # ── OWASP A07 Authentication Failures ────────────────────────────────────
    "hardcodedsecrets": {
        "python": "Move all secrets/credentials to environment variables: os.getenv('SECRET_KEY').",
        "javascript": "Move all secrets to process.env.SECRET_KEY. Use dotenv for local development.",
    },
    "hardcodedcredentials": {
        "python": "Replace hardcoded password/API key with os.getenv('VARIABLE_NAME'). Never hardcode secrets.",
        "javascript": "Replace hardcoded credentials with process.env.VARIABLE_NAME.",
    },
    "defaultcredentials": {
        "python": "Remove all default/hardcoded credentials. Load from environment variables or secrets manager.",
        "javascript": "Remove default credentials. Load from process.env or a secrets manager like HashiCorp Vault.",
    },
    "jwtnone": {
        "python": "Remove 'none' from algorithms list. Use algorithms=['HS256'] or ['RS256'] only.",
        "javascript": "Remove 'none' from algorithms array. Set algorithms: ['HS256'] in jwt.verify options.",
    },
    "jwtweaksecret": {
        "python": "Replace short/weak JWT secret with a strong random value (at least 32 bytes): secrets.token_hex(32).",
        "javascript": "Replace weak JWT secret with a strong random value: crypto.randomBytes(32).toString('hex').",
    },
    "jwtnonealgorithm": {
        "python": "In jwt.decode/verify, explicitly pass algorithms=['HS256'] to prevent 'none' algorithm bypass.",
        "javascript": "Pass { algorithms: ['HS256'] } to jwt.verify() to explicitly reject the 'none' algorithm.",
    },
    "sessionfixation": {
        "python": "After login, regenerate the session: session.clear(); then re-add user data to a new session.",
        "javascript": "After login, call req.session.regenerate() to prevent session fixation attacks.",
    },
    "weakpassword": {
        "python": "Enforce minimum password length and complexity. Hash with bcrypt: bcrypt.hashpw(pwd, bcrypt.gensalt()).",
        "javascript": "Enforce password policy. Hash with bcrypt: await bcrypt.hash(password, 12).",
    },

    # ── OWASP A08 Software & Data Integrity ──────────────────────────────────
    "prototypepollution": {
        "python": "N/A for Python. Validate all merge/update operations against a strict schema.",
        "javascript": (
            "Use Object.create(null) for accumulator objects. Reject '__proto__', "
            "'constructor', 'prototype' keys from user input. Use a safe merge library."
        ),
    },
    "remotescriptexecution": {
        "python": "Never pipe curl/wget output directly to bash/python. Download to a file, verify checksum, then execute.",
        "javascript": "Never pipe downloaded content to exec/eval. Verify integrity (checksum) before execution.",
    },
    "untrustedbinaryexec": {
        "python": "Verify file checksums before execution. Never execute downloaded files without integrity verification.",
        "javascript": "Verify file hash before execution. Use a signed package manager instead of raw downloads.",
    },

    # ── OWASP A09 Logging Failures ────────────────────────────────────────────
    "loggingdisabled": {
        "python": "Re-enable logging: remove logging.disable(). Configure proper log level with logging.basicConfig().",
        "javascript": "Remove console.log = null or logging suppression. Configure proper logging framework.",
    },
    "silentexception": {
        "python": "Replace bare 'except: pass' with 'except Exception as e: logger.error(e)' to log all exceptions.",
        "javascript": "Replace empty catch blocks with catch(err) { logger.error(err); } to log exceptions.",
    },

    # ── OWASP A10 SSRF ────────────────────────────────────────────────────────
    "ssrf": {
        "python": (
            "Validate the target URL against a strict allowlist of hosts. "
            "Use urlparse to extract hostname. Block private IP ranges and metadata endpoints."
        ),
        "javascript": (
            "Validate the target URL against an allowlist of allowed hosts. "
            "Parse with URL class and reject private IPs and cloud metadata endpoints."
        ),
    },
    "serversideforgery": {
        "python": "Validate URL host against allowlist before making requests. Block 169.254.169.254 and internal IPs.",
        "javascript": "Parse the URL and validate hostname against allowlist. Block internal/metadata endpoints.",
    },
    "awsmetadata": {
        "python": "Block requests to 169.254.169.254. Validate all outbound URLs against an allowlist.",
        "javascript": "Block requests to 169.254.169.254. Use IMDSv2 with token if IMDS access is needed.",
    },
    "gcpmetadata": {
        "python": "Block requests to metadata.google.internal and 169.254.169.254.",
        "javascript": "Validate URL hostname against allowlist. Block GCP metadata endpoints.",
    },

    # ── A06 Vulnerable Components ─────────────────────────────────────────────
    "vulnerablecomponents": {
        "python": "Pin dependency versions in requirements.txt. Remove wildcard (*) and VCS (git+) dependencies.",
        "javascript": "Pin exact versions in package.json. Remove wildcard versions and git:// dependencies.",
    },
    "npmregistryhttp": {
        "python": "N/A",
        "javascript": "Change http:// registry URL to https:// in .npmrc. Never use insecure HTTP for npm registry.",
    },
    "pythonvcsdep": {
        "python": "Replace git+/hg+ VCS dependencies with pinned PyPI package versions in requirements.txt.",
        "javascript": "N/A",
    },
}


class PromptBuilder:
    """
    Build deterministic, high-quality prompts for patch generation.
    Covers all 59 vulnerability types detected by the Vulcan engine.
    """

    # Build a direct unified diff generation prompt with few-shot examples and remediation rules.
    @staticmethod
    def build_prompt(
        language: str,
        vuln_type: str,
        cwe: Optional[str],
        owasp: Optional[str],
        vulnerable_slice: str,
        context_before_after: Optional[str],
        taint_path: Optional[list | str],
        sink: Optional[str],
        source: Optional[str],
        file_path: Optional[str] = None,
    ) -> str:
        language   = (language  or "python").lower()
        vuln_key   = (vuln_type or "").lower().replace(" ", "").replace("-", "").replace("_", "")
        rules      = PromptBuilder._rules_for_vuln(language, vuln_key)
        taint_repr = taint_path if isinstance(taint_path, str) else str(taint_path or "")
        context    = (context_before_after or "").strip()
        slice_block = vulnerable_slice.strip()
        diff_file  = file_path.lstrip("/\\") if file_path else "target_file"

        parts = [
            "You are an automated secure code patch generator.",
            "YOUR ONLY OUTPUT IS A VALID UNIFIED DIFF. NO MARKDOWN. NO PROSE. NO EXPLANATION.",
            "Rules:",
            "  1. Start with exactly:  --- a/<filename>",
            "  2. Second line exactly: +++ b/<filename>",
            "  3. Follow with @@ hunk headers and diff lines (+/-/ ).",
            "  4. Minimal fix — change ONLY the vulnerable lines.",
            "  5. Do NOT add new import statements unless strictly required by the fix.",
            "  6. Do NOT alter function signatures or surrounding logic.",
            "  7. Preserve indentation exactly.",
            "",
            _FEW_SHOT,
            "---",
            "NOW GENERATE THE PATCH FOR:",
            f"File:          {diff_file}",
            f"Language:      {language}",
            f"Vulnerability: {vuln_type}",
            f"CWE:           {cwe or 'N/A'}",
            f"OWASP:         {owasp or 'N/A'}",
            f"Source:        {source or 'unknown'}",
            f"Sink:          {sink or 'unknown'}",
            "",
            "Remediation rule (follow exactly):",
            rules,
        ]

        if taint_repr and taint_repr not in ("[]", "None", ""):
            parts += ["", "Taint path (source → sink):", taint_repr]

        if context:
            parts += ["", "Surrounding context (for hunk line numbers):", context]

        parts += [
            "",
            "Vulnerable code slice to patch:",
            slice_block,
            "",
            "OUTPUT FORMAT (copy exactly):",
            f"--- a/{diff_file}",
            f"+++ b/{diff_file}",
            "@@ -<old_start>,<old_len> +<new_start>,<new_len> @@",
            " <unchanged context line>",
            "-<removed vulnerable line>",
            "+<added secure line>",
            "",
            "Output the complete unified diff now:",
        ]

        return "\n".join(parts).strip() + "\n"

    @staticmethod
    def build_cot_reasoning_prompt(
        language: str,
        vuln_type: str,
        cwe: Optional[str],
        owasp: Optional[str],
        vulnerable_slice: str,
        context_before_after: Optional[str],
        taint_path: Optional[list | str],
        sink: Optional[str],
        source: Optional[str],
        file_path: Optional[str] = None,
    ) -> str:
        """
        Legacy 6-question CoT reasoning prompt — kept for test compatibility.
        Prefer build_industrial_cot_prompt() for production generation.
        """
        language  = (language  or "python").lower()
        vuln_key  = (vuln_type or "").lower().replace(" ", "").replace("-", "").replace("_", "")
        rules     = PromptBuilder._rules_for_vuln(language, vuln_key)
        taint_repr = taint_path if isinstance(taint_path, str) else str(taint_path or "")
        context   = (context_before_after or "").strip()
        slice_block = vulnerable_slice.strip()
        diff_file = file_path.lstrip("/\\") if file_path else "target_file"

        parts = [
            "You are a secure code review expert. Analyze the vulnerability below.",
            "Think step by step. Output ONLY structured reasoning — no diff, no code blocks.",
            "",
            f"File:          {diff_file}",
            f"Language:      {language}",
            f"Vulnerability: {vuln_type}",
            f"CWE:           {cwe or 'N/A'}",
            f"OWASP:         {owasp or 'N/A'}",
            f"Source:        {source or 'unknown'}",
            f"Sink:          {sink or 'unknown'}",
            "",
            "Remediation rule:",
            rules,
        ]

        if taint_repr and taint_repr not in ("[]", "None", ""):
            parts += ["", "Taint path (source → sink):", taint_repr]

        if context:
            parts += ["", "Surrounding context:", context]

        parts += [
            "",
            "Vulnerable code:",
            slice_block,
            "",
            "Answer each question concisely and precisely:",
            "1. ROOT CAUSE: What exact pattern makes this code vulnerable?",
            "2. ATTACK VECTOR: How would an attacker exploit this specific code?",
            "3. AFFECTED LINES: Which exact lines must be removed or changed (quote each line)?",
            "4. SECURE REPLACEMENT: What is the exact secure code that replaces each vulnerable line?",
            "5. IMPORTS NEEDED: Any new imports required by the fix? (list or 'none')",
            "6. RISK OF CHANGE: What could break if the fix is applied incorrectly?",
        ]

        return "\n".join(parts).strip() + "\n"

    @staticmethod
    def build_industrial_cot_prompt(
        language: str,
        vuln_type: str,
        cwe: Optional[str],
        owasp: Optional[str],
        vulnerable_slice: str,
        context_before_after: Optional[str],
        taint_path: Optional[list | str],
        sink: Optional[str],
        source: Optional[str],
        file_path: Optional[str] = None,
    ) -> str:
        """
        Industrial-grade 4-phase adversarial Chain-of-Thought prompt.

        Modelled after the security analysis protocols used in production
        AI security tools (Snyk, Semgrep, GitHub Advanced Security) and
        academic research on LLM-based patch generation (VulRepair, SWE-bench).

        PHASE 1 — THREAT MODELING
          Forces the model to think like an attacker first: map the full
          attack surface, construct a concrete exploit payload, estimate CVSS.

        PHASE 2 — FIX DESIGN
          Least-to-most decomposition: identify root cause → name the secure
          API → specify exact REMOVE/ADD lines → enumerate new imports →
          rate breakage risk. Grounds the model on minimal-change principle.

        PHASE 3 — ADVERSARIAL SELF-VERIFICATION
          The model now plays the role of attacker against its own proposed fix.
          It must try every bypass (encoding, type coercion, edge cases) and
          either confirm the fix is complete or strengthen it. This is the key
          step missing from standard CoT implementations.

        PHASE 4 — FORMAL PATCH SPECIFICATION
          Produces a machine-readable PATCH_SPEC_BEGIN...PATCH_SPEC_END block
          that the diff generator reads in Call 2. The spec is the formal
          contract: REMOVE[N]/ADD[N] lines, NEW_IMPORT, BREAKAGE_RISK, and
          BYPASS_FOUND flag. Eliminates ambiguity between reasoning and diff.

        Output: plain structured text ending with the PATCH_SPEC block.
        """
        language    = (language  or "python").lower()
        vuln_key    = (vuln_type or "").lower().replace(" ", "").replace("-", "").replace("_", "")
        rules       = PromptBuilder._rules_for_vuln(language, vuln_key)
        taint_repr  = taint_path if isinstance(taint_path, str) else str(taint_path or "")
        context     = (context_before_after or "").strip()
        slice_block = vulnerable_slice.strip()
        diff_file   = file_path.lstrip("/\\") if file_path else "target_file"

        bar = "═" * 60

        parts = [
            bar,
            "VULNERABILITY SECURITY ANALYSIS — CHAIN-OF-THOUGHT PROTOCOL",
            bar,
            "",
            "You are a Principal Security Engineer conducting a formal code security review.",
            "Work through the four phases below with precision and adversarial rigour.",
            "Output ONLY plain structured text following this exact protocol.",
            "NO diffs. NO code blocks. NO markdown. NO backticks.",
            "",
            "─" * 40,
            "VULNERABILITY PROFILE",
            "─" * 40,
            f"File:          {diff_file}",
            f"Language:      {language.upper()}",
            f"Type:          {vuln_type}",
            f"CWE:           {cwe or 'N/A'}",
            f"OWASP:         {owasp or 'N/A'}",
            f"Taint Source:  {source or 'unknown'}",
            f"Taint Sink:    {sink or 'unknown'}",
            "",
            "AUTHORITATIVE REMEDIATION RULE:",
            rules,
        ]

        if taint_repr and taint_repr not in ("[]", "None", ""):
            parts += [
                "",
                "TAINT FLOW PATH (source → sink):",
                taint_repr,
            ]

        if context:
            parts += [
                "",
                "SURROUNDING CODE CONTEXT:",
                context,
            ]

        parts += [
            "",
            "VULNERABLE CODE SLICE:",
            slice_block,
            "",
            bar,
            "PHASE 1 — THREAT MODELING",
            bar,
            "",
            "T1.1  ATTACK SURFACE",
            "      Identify every user-controlled input that flows into the vulnerable code.",
            "      For each input point state: input name, entry method, and path to the sink.",
            "",
            "T1.2  CONCRETE EXPLOIT",
            "      Write one concrete exploit payload that would succeed against this exact code.",
            "      Be specific — show exact values, HTTP parameters, or API calls.",
            "",
            "T1.3  ATTACK OUTCOME",
            "      What can a successful attacker achieve?",
            "      (data exfiltration / RCE / privilege escalation / DoS / other)",
            "",
            "T1.4  CVSS 3.1 ESTIMATE",
            "      State: AV / AC / PR / UI / S / C / I / A and rough base score (0.0–10.0).",
            "",
            bar,
            "PHASE 2 — FIX DESIGN",
            bar,
            "",
            "F2.1  ROOT CAUSE (one sentence)",
            "      State the exact coding anti-pattern that creates the vulnerability.",
            "",
            "F2.2  SECURE PATTERN",
            "      Name the exact secure API, function, or library that replaces the vulnerable one.",
            "      Explain in one sentence why this alternative is safe against the Phase 1 exploit.",
            "",
            "F2.3  MINIMAL CHANGE SPECIFICATION",
            "      List ONLY the lines that must change. Use this format for each:",
            "        REMOVE: \"<exact vulnerable line as it appears in the code>\"",
            "        ADD:    \"<exact secure replacement line>\"",
            "      Quote lines verbatim. Preserve indentation.",
            "",
            "F2.4  NEW IMPORTS / REQUIRES",
            "      List every new import or require statement the fix needs.",
            "      State 'none' if no new imports are needed.",
            "",
            "F2.5  BREAKAGE RISK",
            "      Rate: LOW / MEDIUM / HIGH.",
            "      Explain: which callers, tests, or behaviours might break?",
            "",
            bar,
            "PHASE 3 — ADVERSARIAL SELF-VERIFICATION",
            bar,
            "",
            "A3.1  BYPASS ANALYSIS",
            "      Switch role: you are now an attacker reviewing the fix in F2.3.",
            "      Try every bypass technique:",
            "        - Encoding variations (URL-encode, unicode, hex escapes)",
            "        - Type coercion (pass int/array where string expected)",
            "        - Null/empty/boundary inputs",
            "        - Second-order injection (stored then retrieved)",
            "        - Race conditions or TOCTOU",
            "      Answer YES (the fix can be bypassed — explain how) or",
            "              NO  (the fix is complete — explain why each bypass fails).",
            "",
            "A3.2  FIX STRENGTHENING",
            "      If A3.1 is YES, state the amended REMOVE/ADD lines that close the bypass.",
            "      If A3.1 is NO, repeat the F2.3 specification unchanged.",
            "",
            "A3.3  FINAL VERDICT",
            "      State the definitive secure replacement after adversarial review.",
            "      This is the authoritative specification the diff generator will use.",
            "",
            bar,
            "PHASE 4 — FORMAL PATCH SPECIFICATION",
            bar,
            "",
            "Output this exact block at the end of your analysis.",
            "Fill in <placeholders>. Use one REMOVE/ADD pair per changed line.",
            "If more than one line changes, add REMOVE[2]/ADD[2], REMOVE[3]/ADD[3], etc.",
            "",
            "PATCH_SPEC_BEGIN",
            f"FILE: {diff_file}",
            f"LANGUAGE: {language}",
            f"VULN_TYPE: {vuln_type}",
            "CHANGE_COUNT: <number of lines changed>",
            "REMOVE[1]: <exact vulnerable line verbatim>",
            "ADD[1]:    <exact secure replacement verbatim>",
            "NEW_IMPORT[1]: <import statement or NONE>",
            "BREAKAGE_RISK: <LOW|MEDIUM|HIGH>",
            "BYPASS_FOUND: <YES|NO>",
            "PATCH_SPEC_END",
        ]

        return "\n".join(parts).strip() + "\n"

    @staticmethod
    def build_attack_test_prompt(
        vuln_type: str,
        cwe: Optional[str],
        language: str,
        vulnerable_slice: str,
        unified_diff: str,
        source: Optional[str] = None,
        sink: Optional[str] = None,
    ) -> str:
        """
        Adversarial patch attack simulation prompt.

        Runs AFTER a patch is generated. A separate LLM call plays the role
        of a penetration tester who:
          1. Knows the original vulnerability type and CWE
          2. Has the original vulnerable code
          3. Has the generated patch (unified diff)
          4. Tries 5 specific attack techniques against the secured code

        Each attack reports BLOCKED or BYPASSED with an explanation.
        The model then gives an OVERALL verdict and a recommendation.

        Output format: structured ATTACK_TEST_BEGIN...END block for
        machine-readable parsing.
        """
        language = (language or "python").lower()
        bar = "═" * 60

        return "\n".join([
            bar,
            "ADVERSARIAL PATCH ATTACK SIMULATION",
            bar,
            "",
            "You are a senior penetration tester reviewing a security patch.",
            "Your mission: attempt to bypass the patch and determine if the secured",
            "code is still exploitable. Be rigorous — assume a skilled attacker.",
            "",
            "Output ONLY the structured ATTACK_TEST_BEGIN block below.",
            "NO other text. NO markdown. NO code fences.",
            "",
            "─" * 40,
            "TARGET PROFILE",
            "─" * 40,
            f"Vulnerability:  {vuln_type}",
            f"CWE:            {cwe or 'N/A'}",
            f"Language:       {language.upper()}",
            f"Taint Source:   {source or 'user input'}",
            f"Taint Sink:     {sink or 'unknown'}",
            "",
            "ORIGINAL VULNERABLE CODE:",
            vulnerable_slice.strip(),
            "",
            "PATCH APPLIED (unified diff):",
            unified_diff.strip(),
            "",
            "─" * 40,
            "ATTACK PROTOCOL",
            "─" * 40,
            "",
            "For each technique, apply it against the SECURED code (after patch).",
            "State BLOCKED if the patch prevents it, BYPASSED if it succeeds.",
            "",
            "TECHNIQUE 1 — Direct Payload",
            f"  Craft the standard {vuln_type} payload and submit it directly.",
            "  Does the secured code prevent this?",
            "",
            "TECHNIQUE 2 — Encoding Bypass",
            "  Apply URL-encoding (%27), unicode escapes (\\u0027), double-encoding (%2527),",
            "  or hex escapes on the malicious payload. Does encoding evade the fix?",
            "",
            "TECHNIQUE 3 — Type Coercion",
            "  Submit an array, object, integer, boolean, or null instead of a string.",
            "  Does the fix handle unexpected types safely?",
            "",
            "TECHNIQUE 4 — Boundary & Edge Cases",
            "  Try: empty string, null bytes (\\x00), very long input (10 000+ chars),",
            "  newlines (\\r\\n), Unicode control characters. Any bypass?",
            "",
            "TECHNIQUE 5 — Second-Order Attack",
            "  Store a malicious payload in the database/session/file, then retrieve",
            "  and process it later. Does the patch protect stored-then-retrieved data?",
            "",
            "─" * 40,
            "OUTPUT FORMAT (copy exactly — fill placeholders)",
            "─" * 40,
            "",
            "ATTACK_TEST_BEGIN",
            "ATTACK[1].NAME: Direct Payload",
            "ATTACK[1].RESULT: <BLOCKED|BYPASSED>",
            "ATTACK[1].REASON: <one sentence>",
            "",
            "ATTACK[2].NAME: Encoding Bypass",
            "ATTACK[2].RESULT: <BLOCKED|BYPASSED>",
            "ATTACK[2].REASON: <one sentence>",
            "",
            "ATTACK[3].NAME: Type Coercion",
            "ATTACK[3].RESULT: <BLOCKED|BYPASSED>",
            "ATTACK[3].REASON: <one sentence>",
            "",
            "ATTACK[4].NAME: Boundary & Edge Cases",
            "ATTACK[4].RESULT: <BLOCKED|BYPASSED>",
            "ATTACK[4].REASON: <one sentence>",
            "",
            "ATTACK[5].NAME: Second-Order Attack",
            "ATTACK[5].RESULT: <BLOCKED|BYPASSED>",
            "ATTACK[5].REASON: <one sentence>",
            "",
            "OVERALL: <SECURE|VULNERABLE>",
            "PATCH_CONFIDENCE: <0-100>",
            "RECOMMENDATION: <one sentence — defense-in-depth suggestion>",
            "ATTACK_TEST_END",
        ]).strip() + "\n"

    @staticmethod
    def build_critique_prompt(
        original_prompt: str,
        failed_diff: str,
        failures: list,
    ) -> str:
        """
        Self-critique prompt — shown to the model after a failed attempt.
        Follows the 'generate → critique → regenerate' pattern used in
        production AI coding assistants (GitHub Copilot, AlphaCode).
        """
        failure_lines = "\n".join(
            f"  - [{f.name}] {f.details}" for f in failures
        )
        return "\n".join([
            "CORRECTION REQUIRED — your previous patch failed validation.",
            "",
            "Validation failures:",
            failure_lines,
            "",
            "Your failed patch was:",
            "```",
            failed_diff.strip(),
            "```",
            "",
            "Fix every failure listed above and regenerate the patch.",
            "YOUR ONLY OUTPUT IS A VALID UNIFIED DIFF. NO MARKDOWN. NO PROSE.",
            "─" * 60,
            "",
            original_prompt,
        ])

    # Look up the best-matching remediation rule for the given language and normalized vuln key.
    @staticmethod
    def _rules_for_vuln(language: str, vuln_key: str) -> str:
        lang = "python" if language.startswith("py") else "javascript"
        # Try longest key match first for specificity
        best_match = None
        best_len = 0
        for key, rule_map in _RULES.items():
            clean_key = key.replace(" ", "").replace("-", "").replace("_", "")
            if clean_key in vuln_key or vuln_key in clean_key:
                if len(clean_key) > best_len:
                    best_len = len(clean_key)
                    best_match = rule_map
        if best_match:
            return best_match.get(lang, best_match.get("python",
                "Apply secure coding best practices."))
        return (
            "Apply the minimal secure fix for this vulnerability type. "
            "Follow OWASP and CWE remediation guidance. "
            "Remove the vulnerable pattern and replace with a safe alternative."
        )
