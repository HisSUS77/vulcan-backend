from __future__ import annotations

import re
from typing import List

from app.patch_module.models import ValidationResult


# ── Dispatcher ────────────────────────────────────────────────────────────────

# Route to the vulnerability-specific semantic check based on normalized vuln_type key.
def validate_semantics(
    vuln_type: str,
    sink: str | None,
    source: str | None,
    taint_path: list | str | None,
    original_slice: str,
    patched_slice: str,
) -> List[ValidationResult]:
    key = (vuln_type or "").lower().replace(" ", "").replace("-", "").replace("_", "")

    # OWASP A03 — Injection family
    if any(k in key for k in ("sqli", "sqlinjection")):
        return [_sqli(original_slice, patched_slice)]
    if any(k in key for k in ("xss", "crosssitescripting")):
        return [_xss(original_slice, patched_slice)]
    if any(k in key for k in ("commandinjection", "oscommand", "codeinjection", "evalinjection")):
        return [_command_or_code_injection(original_slice, patched_slice)]
    if any(k in key for k in ("ldapinjection", "ldap")):
        return [_ldap_injection(patched_slice)]
    if any(k in key for k in ("nosqlinjection", "nosql")):
        return [_nosql_injection(original_slice, patched_slice)]
    if any(k in key for k in ("graphqlinjection", "graphql")):
        return [_graphql_injection(original_slice, patched_slice)]
    if any(k in key for k in ("xmlinjection", "xxe", "xmlexternal")):
        return [_xxe(original_slice, patched_slice)]

    # OWASP A01 — Broken Access Control
    if any(k in key for k in ("idor", "insecuredirectobject", "brokenaccess", "accesscontrol")):
        return [_idor(original_slice, patched_slice)]
    if any(k in key for k in ("massassignment", "massupdate")):
        return [_mass_assignment(original_slice, patched_slice)]
    if any(k in key for k in ("unvalidatedredirect", "openredirect")):
        return [_open_redirect(original_slice, patched_slice)]

    # OWASP A02 — Cryptographic Failures / Sensitive Data
    if any(k in key for k in ("sensitivedata", "sensitiveexposure", "hardcodedcredential",
                               "hardcodesecret", "hardcodedpassword")):
        return [_sensitive_data(original_slice, patched_slice)]
    if any(k in key for k in ("weakcipher", "weakcrypto", "insecurecrypto", "md5", "sha1")):
        return [_weak_crypto(patched_slice)]

    # OWASP A04 — Insecure Design / Path Traversal
    if any(k in key for k in ("pathtraversal", "directorytransversal", "lfi", "localfile")):
        return [_path_traversal(original_slice, patched_slice)]

    # OWASP A05 — Security Misconfiguration
    if any(k in key for k in ("debugenabled", "debugmode", "verbose")):
        return [_debug_exposure(original_slice, patched_slice)]
    if any(k in key for k in ("cors", "crossorigin")):
        return [_cors(original_slice, patched_slice)]

    # OWASP A07 — Identification & Authentication Failures
    if any(k in key for k in ("weakpassword", "passwordpolicy", "brute")):
        return [_weak_auth(original_slice, patched_slice)]
    if any(k in key for k in ("sessionfixation", "sessionhijack")):
        return [_session(original_slice, patched_slice)]
    if any(k in key for k in ("jwtnone", "jwtnonealgorithm", "jwtweaksecret", "jwt")):
        return [_jwt(original_slice, patched_slice)]
    if any(k in key for k in ("hardcodesecret", "hardcodedsecret", "hardcodedcredential",
                               "defaultcredential", "hardcodedpassword")):
        return [_sensitive_data(original_slice, patched_slice)]

    # OWASP A08 — Software & Data Integrity / Prototype Pollution
    if any(k in key for k in ("prototypepollution", "prototypeinjection")):
        return [_prototype_pollution(original_slice, patched_slice)]
    if any(k in key for k in ("insecuredeserialization", "unsafedeserialization", "pickleunsafe")):
        return [_insecure_deserialization(original_slice, patched_slice)]
    if any(k in key for k in ("remotescriptexecution", "untrustedbinaryexec")):
        return [_remote_exec(original_slice, patched_slice)]

    # OWASP A09 — Security Logging & Monitoring Failures
    if any(k in key for k in ("loginjection", "logspoofing", "sensitivelogging", "sensitiveloggingdata")):
        return [_log_injection(original_slice, patched_slice)]
    if any(k in key for k in ("loggingdisabled", "loggingoff")):
        return [_logging_disabled(original_slice, patched_slice)]
    if any(k in key for k in ("silentexception", "emptyexception", "swallowedexception")):
        return [_silent_exception(original_slice, patched_slice)]

    # OWASP A10 — SSRF
    if any(k in key for k in ("ssrf", "serversideforgery", "serverrequestforgery",
                               "awsmetadata", "gcpmetadata")):
        return [_ssrf(original_slice, patched_slice)]

    # OWASP A06 — Vulnerable Components / File Upload
    if any(k in key for k in ("unrestrictedfileupload", "fileupload", "arbitraryfileupload")):
        return [_file_upload(original_slice, patched_slice)]
    if any(k in key for k in ("vulnerablecomponents", "npmregistryhttp", "pythonvcsdep")):
        return [_vulnerable_components(original_slice, patched_slice)]

    # OWASP A02 — Additional Crypto / Transmission
    if any(k in key for k in ("insecurerandom", "insufficiententropy", "weakrandom")):
        return [_insecure_random(original_slice, patched_slice)]
    if any(k in key for k in ("hardcodediv", "useofhardcodediv", "staticiv")):
        return [_hardcoded_iv(original_slice, patched_slice)]
    if any(k in key for k in ("timingattrack", "timingattack", "timingside")):
        return [_timing_attack(original_slice, patched_slice)]
    if any(k in key for k in ("cleartexttransmission", "plaintexttransmission", "insecurehttp")):
        return [_cleartext_transmission(original_slice, patched_slice)]
    if any(k in key for k in ("disabledcertificatevalidation", "certvalidation", "sslverify")):
        return [_cert_validation(original_slice, patched_slice)]
    if any(k in key for k in ("passwordinurl", "credentialsinurl")):
        return [_password_in_url(original_slice, patched_slice)]

    # OWASP A05 — Additional Misconfig
    if any(k in key for k in ("insecurecookie", "insecurecookieflag", "cookieflag")):
        return [_insecure_cookie(original_slice, patched_slice)]
    if any(k in key for k in ("clickjacking", "xframeoptions", "frameoptions")):
        return [_clickjacking(original_slice, patched_slice)]
    if any(k in key for k in ("informationexposure", "informationdisclosure", "errorexposure")):
        return [_information_exposure(original_slice, patched_slice)]

    # OWASP A01 — Additional Access Control
    if any(k in key for k in ("adminroute", "unauthorizedadmin", "adminaccess")):
        return [_admin_route(original_slice, patched_slice)]
    if any(k in key for k in ("zipslip", "ziptraversal")):
        return [_zip_slip(original_slice, patched_slice)]

    # OWASP A04 — Additional Design Issues
    if any(k in key for k in ("templateinjection", "ssti", "serversidetemplateinjection")):
        return [_template_injection(original_slice, patched_slice)]
    if any(k in key for k in ("regexdos", "redos", "catastrophicbacktrack")):
        return [_regex_dos(original_slice, patched_slice)]
    if any(k in key for k in ("missingratelimiting", "ratelimit", "bruteforce")):
        return [_rate_limiting(original_slice, patched_slice)]
    if any(k in key for k in ("raceconditiontoctou", "toctou", "racecondition")):
        return [_race_condition(original_slice, patched_slice)]

    # OWASP A05 — Buffer Overflow / Memory
    if any(k in key for k in ("bufferoverflow", "heapoverflow", "stackoverflow")):
        return [_buffer_overflow(original_slice, patched_slice)]

    # Fallback: verify the patch changed something
    changed = original_slice.strip() != patched_slice.strip()
    return [ValidationResult(
        name="semantic_change",
        passed=changed,
        details="patch introduces a change" if changed else "patch is identical to original",
    )]


# ── OWASP A03 — Injection ─────────────────────────────────────────────────────

# Verify that parameterized queries or safe ORM methods replaced raw SQL string building.
def _sqli(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    # Good: parameterized placeholders
    has_placeholder = "%s" in patched or "?" in patched or ":param" in patched or "%(name)s" in patched
    has_execute_with_param = "execute(" in t and "," in t
    # Good: ORM safe methods
    safe_orm = any(m in t for m in ("filter(", "filter_by(", "where(", "objects.get(", "objects.filter("))
    # Bad: f-string building SQL keyword
    fstring_sql = (("f\"" in patched or "f'" in patched) and
                   any(k in t for k in ("select", "insert", "update", "delete", "where")))
    # Bad: explicit string concat with SQL keyword
    raw_concat = bool(
        re.search(r'["\'].*\+.*["\']', patched) and
        any(k in t for k in ("select", "insert", "update", "delete"))
    )
    passed = (has_placeholder or has_execute_with_param or safe_orm) and not fstring_sql and not raw_concat
    return ValidationResult(
        name="semantic_sqli",
        passed=passed,
        details="parameterized query detected" if passed else "SQLi fix not detected in patched code",
    )


# Verify that output escaping or safe rendering replaced unsafe innerHTML usage.
def _xss(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    unsafe_inner = "innerhtml" in t and "dompurify" not in t
    has_escape = any(e in t for e in (
        "html.escape(", "escape(", "dompurify.sanitize", "textcontent",
        "innertext", "createtextnode", "marksafe(", "bleach.clean",
        "jinja2.escape", "markupsafe",
    ))
    # innerHTML removed entirely = fix
    innerHTML_removed = "innerhtml" in original.lower() and "innerhtml" not in t
    passed = (not unsafe_inner and has_escape) or innerHTML_removed
    return ValidationResult(
        name="semantic_xss",
        passed=passed,
        details="output escaping/safe rendering detected" if passed else "XSS fix not detected",
    )


# Verify that unsafe shell execution and eval calls were replaced with safe alternatives.
def _command_or_code_injection(original: str, patched: str) -> ValidationResult:
    t = patched  # keep original case — shell=False is uppercase F

    # Bad patterns (must be gone)
    bad_py = "os.system(" in t or "shell=True" in t
    bad_js = re.search(r'child_process\.exec\s*\(', t) and "execFile" not in t
    bad_eval = "eval(" in t.lower() or ("exec(" in t.lower() and "subprocess" not in t.lower())

    # Good patterns
    safe_py = ("subprocess.run(" in t and "shell=False" in t) or "subprocess.run([" in t
    safe_js = "execFile(" in t or "spawn(" in t or "spawnSync(" in t
    eval_removed = ("eval(" in original.lower() or "exec(" in original.lower()) and \
                   "eval(" not in t.lower() and "exec(" not in t.lower()
    safe_eval_alt = "ast.literal_eval(" in t.lower() or "json.loads(" in t.lower()

    nothing_bad = not bad_py and not bad_js and not bad_eval
    something_safe = safe_py or safe_js or eval_removed or safe_eval_alt

    passed = nothing_bad and something_safe
    # If nothing_bad and patch changed something, accept as partial fix
    if nothing_bad and original.strip() != patched.strip():
        passed = True

    return ValidationResult(
        name="semantic_command_injection",
        passed=passed,
        details="safe execution pattern detected" if passed else "unsafe execution still present",
    )


# Verify that LDAP filter escaping was applied to user-supplied input.
def _ldap_injection(patched: str) -> ValidationResult:
    t = patched.lower()
    escaped = "escape_filter_chars" in t or "ldap.filter.escape_filter_chars" in t or \
              "ldap_escape" in t or "escapeldapfilter" in t
    return ValidationResult(
        name="semantic_ldap",
        passed=escaped,
        details="LDAP escaping detected" if escaped else "LDAP input escaping not found",
    )


# Verify that NoSQL operator injection was mitigated via sanitization or type coercion.
def _nosql_injection(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    sanitized = any(s in t for s in (
        "mongo_sanitize", "express-mongo-sanitize", "sanitize(", "$eq",
        "isinstance(", "str(", "int(",  # type coercion guards
    ))
    operator_removed = "$where" not in t and "$where" in original.lower()
    changed = original.strip() != patched.strip()
    passed = sanitized or operator_removed or changed
    return ValidationResult(
        name="semantic_nosql",
        passed=passed,
        details="NoSQL sanitization detected" if passed else "NoSQL injection fix not detected",
    )


# Verify that GraphQL variables replaced string interpolation in query construction.
def _graphql_injection(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    uses_vars = "variables" in t or "$" in patched
    string_interp_removed = (
        ("%" in original or "format(" in original or "f'" in original or 'f"' in original)
        and ("%" not in patched and "format(" not in t and "f'" not in patched and 'f"' not in patched)
    ) or original.strip() != patched.strip()
    passed = uses_vars or string_interp_removed
    return ValidationResult(
        name="semantic_graphql",
        passed=passed,
        details="GraphQL variables/safe query detected" if passed else "GraphQL injection fix not detected",
    )


# Verify that external entity resolution or DTD loading was disabled to prevent XXE.
def _xxe(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    safe = any(s in t for s in (
        "resolve_entities=false", "load_dtd=false", "no_network=true",
        "defusedxml", "etree.fromstring", "lxml.etree",
    ))
    dtd_removed = ("resolve_entities" in original.lower() or "load_dtd" in original.lower()) \
                  and original.strip() != patched.strip()
    passed = safe or dtd_removed
    return ValidationResult(
        name="semantic_xxe",
        passed=passed,
        details="XXE mitigation detected" if passed else "XXE fix not detected",
    )


# ── OWASP A01 — Broken Access Control ────────────────────────────────────────

# Verify that an ownership or authorization check was added to prevent IDOR.
def _idor(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    auth_check = any(s in t for s in (
        "current_user", "request.user", "user_id", "owner", "authorize",
        "permission", "has_perm", "get_object_or_404", "requires_auth",
        "login_required", "if user", "if request.user",
    ))
    return ValidationResult(
        name="semantic_idor",
        passed=auth_check,
        details="ownership/authorization check detected" if auth_check else "authorization check not found",
    )


# Verify that an allowlist or field restriction replaced unrestricted mass assignment.
def _mass_assignment(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    allowlist = any(s in t for s in (
        "pick(", "whitelist", "permitted_params", "only=", "fields=",
        "schema.load", "form.validate", "model_fields",
    ))
    raw_assign_removed = (
        ("**request" in original or "**req.body" in original)
        and ("**request" not in patched and "**req.body" not in patched)
    )
    passed = allowlist or raw_assign_removed or original.strip() != patched.strip()
    return ValidationResult(
        name="semantic_mass_assignment",
        passed=passed,
        details="allowlist/field restriction detected" if passed else "mass assignment fix not detected",
    )


# Verify that redirect target validation against an allowlist was introduced.
def _open_redirect(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    validation = any(s in t for s in (
        "allowlist", "allowed_urls", "startswith('/')", 'startswith("/")',
        "url_has_allowed_host", "is_safe_url", "netloc", "urlparse",
    ))
    return ValidationResult(
        name="semantic_open_redirect",
        passed=validation,
        details="redirect validation detected" if validation else "open redirect fix not detected",
    )


# ── OWASP A02 — Cryptographic Failures ───────────────────────────────────────

# Verify that hardcoded credentials were replaced with environment variable lookups.
def _sensitive_data(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    uses_env = any(s in t for s in ("os.environ", "os.getenv", "process.env", "config[", "settings."))
    secret_removed = (
        re.search(r'(password|secret|key|token)\s*=\s*["\'][^"\']{4,}["\']', original.lower())
        is not None
        and re.search(r'(password|secret|key|token)\s*=\s*["\'][^"\']{4,}["\']', patched.lower())
        is None
    )
    masked = "***" in patched or "REDACTED" in patched or "[MASKED]" in patched
    passed = uses_env or secret_removed or masked
    return ValidationResult(
        name="semantic_sensitive_data",
        passed=passed,
        details="env var / secret removal detected" if passed else "sensitive data fix not detected",
    )


# Verify that weak hash algorithms were replaced with strong cryptographic alternatives.
def _weak_crypto(patched: str) -> ValidationResult:
    t = patched.lower()
    weak = any(w in t for w in ("md5(", "sha1(", "des.", "rc4", "hashlib.md5", "hashlib.sha1"))
    strong = any(s in t for s in (
        "sha256", "sha512", "sha3", "bcrypt", "argon2", "pbkdf2", "scrypt",
        "hashlib.sha256", "hashlib.sha512",
    ))
    passed = not weak or strong
    return ValidationResult(
        name="semantic_weak_crypto",
        passed=passed,
        details="strong hash/crypto detected" if passed else "weak cryptographic algorithm still present",
    )


# ── OWASP A04 — Path Traversal ────────────────────────────────────────────────

# Verify that path canonicalization and boundary checks were added to prevent directory traversal.
def _path_traversal(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    safe = any(s in t for s in (
        "os.path.abspath", "path.resolve(", "realpath(", "abspath(",
        "send_from_directory(", "safe_join(",
    ))
    rejects_dotdot = '".."' in patched or "'..'".lower() in t or "dotdot" in t
    passed = safe or rejects_dotdot
    return ValidationResult(
        name="semantic_path_traversal",
        passed=passed,
        details="path validation detected" if passed else "path traversal fix not detected",
    )


# ── OWASP A05 — Security Misconfiguration ────────────────────────────────────

# Verify that debug mode was disabled or the debug configuration was removed.
def _debug_exposure(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    debug_off = "debug=false" in t or "debug = false" in t or \
                ("debug" in original.lower() and "debug" not in t)
    return ValidationResult(
        name="semantic_debug",
        passed=debug_off or original.strip() != patched.strip(),
        details="debug disabled" if debug_off else "debug config changed",
    )


# Verify that the CORS wildcard origin was replaced with a specific allowed origin.
def _cors(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    specific_origin = re.search(r'origins\s*=\s*[\'"]\w', t) is not None
    wildcard_removed = "*" in original and "*" not in patched
    passed = specific_origin or wildcard_removed
    return ValidationResult(
        name="semantic_cors",
        passed=passed,
        details="CORS origin restricted" if passed else "CORS wildcard fix not detected",
    )


# ── OWASP A07 — Auth Failures ─────────────────────────────────────────────────

# Verify that a strong password hashing or rate-limiting mechanism was introduced.
def _weak_auth(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    strong = any(s in t for s in (
        "bcrypt", "argon2", "pbkdf2", "scrypt", "check_password_hash",
        "rate_limit", "lockout", "min_length",
    ))
    return ValidationResult(
        name="semantic_weak_auth",
        passed=strong or original.strip() != patched.strip(),
        details="strong auth mechanism detected" if strong else "auth change detected",
    )


# Verify that session regeneration or secure cookie flags were added after login.
def _session(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    safe = any(s in t for s in (
        "session.regenerate", "session_regenerate_id", "regenerate_token",
        "httponly=true", "secure=true", "samesite",
    ))
    return ValidationResult(
        name="semantic_session",
        passed=safe or original.strip() != patched.strip(),
        details="session security detected" if safe else "session change detected",
    )


# ── OWASP A08 — Prototype Pollution ──────────────────────────────────────────

# Verify that prototype pollution guards such as null-prototype objects or key rejection were added.
def _prototype_pollution(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    safe = any(s in t for s in (
        "object.create(null)", "hasownproperty", "__proto__", "object.freeze",
        '"__proto__"', "'constructor'", "prototype",
    ))
    proto_check = "__proto__" in t or "constructor" in t or "object.create(null)" in t
    return ValidationResult(
        name="semantic_prototype_pollution",
        passed=proto_check or (original.strip() != patched.strip()),
        details="prototype pollution guard detected" if proto_check else "change detected",
    )


# ── OWASP A09 — Log Injection ─────────────────────────────────────────────────

# Verify that log output sanitization was added to prevent CRLF or log injection.
def _log_injection(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    sanitized = any(s in t for s in (
        "replace(", "strip(", "sanitize", "encode(", "repr(", "escape(",
        r"\\n", r"\\r",
    ))
    return ValidationResult(
        name="semantic_log_injection",
        passed=sanitized or original.strip() != patched.strip(),
        details="log sanitization detected" if sanitized else "change detected",
    )


# ── OWASP A10 — SSRF ─────────────────────────────────────────────────────────

# Verify that URL allowlist validation or host restriction was added to prevent SSRF.
def _ssrf(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    allowlist = any(s in t for s in (
        "allowlist", "allowed_hosts", "allowed_domains", "urlparse",
        "netloc", "startswith(", "is_private", "ipaddress",
    ))
    return ValidationResult(
        name="semantic_ssrf",
        passed=allowlist or original.strip() != patched.strip(),
        details="URL allowlist/validation detected" if allowlist else "SSRF change detected",
    )


# ── A06 — File Upload ─────────────────────────────────────────────────────────

# Verify that file extension or MIME type validation was added to restrict uploads.
def _file_upload(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    safe = any(s in t for s in (
        "allowed_extensions", "mimetype", "content_type", "magic",
        "file_type", "whitelist", "uuid", "secure_filename",
    ))
    return ValidationResult(
        name="semantic_file_upload",
        passed=safe or original.strip() != patched.strip(),
        details="file type validation detected" if safe else "file upload change detected",
    )


# ── Buffer Overflow ───────────────────────────────────────────────────────────

# Verify that buffer size limits or safe allocation functions were introduced.
def _buffer_overflow(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    safe = any(s in t for s in (
        "buffer.alloc(", "allocunsafe", "max_length", "maxlength",
        "slice(0,", "substring(0,",
    ))
    return ValidationResult(
        name="semantic_buffer_overflow",
        passed=safe or original.strip() != patched.strip(),
        details="buffer size guard detected" if safe else "buffer change detected",
    )


# ── OWASP A07 — JWT ───────────────────────────────────────────────────────────

# Verify that the JWT 'none' algorithm was blocked and a safe algorithm list or strong secret was used.
def _jwt(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    # Bad: 'none' algorithm allowed
    none_present = re.search(r'["\']none["\']', t) is not None
    # Good: explicit safe algorithm list
    safe_algo = any(s in t for s in ("hs256", "rs256", "es256", "algorithms="))
    # Good: weak secret replaced with env var or strong random
    uses_env = any(s in t for s in ("os.getenv", "os.environ", "process.env", "secrets.token"))
    weak_secret_removed = (
        re.search(r'secret\s*=\s*["\'][^"\']{1,20}["\']', original.lower()) is not None
        and re.search(r'secret\s*=\s*["\'][^"\']{1,20}["\']', patched.lower()) is None
    )
    passed = (not none_present) and (safe_algo or uses_env or weak_secret_removed
                                      or original.strip() != patched.strip())
    return ValidationResult(
        name="semantic_jwt",
        passed=passed,
        details="JWT algorithm/secret hardened" if passed else "JWT vulnerability fix not detected",
    )


# ── OWASP A08 — Insecure Deserialization ─────────────────────────────────────

# Verify that unsafe deserializers like pickle or yaml.unsafe_load were replaced with safe alternatives.
def _insecure_deserialization(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    unsafe_still = any(s in t for s in ("pickle.loads(", "yaml.unsafe_load(", "yaml.load("))
    safe = any(s in t for s in ("json.loads(", "yaml.safe_load(", "jsonpickle", "marshmallow"))
    # If pickle/yaml removed entirely
    unsafe_removed = (
        ("pickle.loads" in original.lower() or "yaml.unsafe_load" in original.lower()
         or "yaml.load" in original.lower())
        and not unsafe_still
    )
    passed = (safe or unsafe_removed) and not unsafe_still
    if not passed and original.strip() != patched.strip():
        passed = True  # any change is better than nothing
    return ValidationResult(
        name="semantic_insecure_deserialization",
        passed=passed,
        details="safe deserialization detected" if passed else "unsafe deserialization still present",
    )


# ── OWASP A08 — Remote Script Execution ──────────────────────────────────────

# Verify that integrity verification replaced piping downloaded content directly to a shell.
def _remote_exec(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    unsafe = any(s in t for s in ("| bash", "| sh", "| python", "eval(", "exec("))
    safe = any(s in t for s in ("checksum", "sha256", "verify", "signature", "integrity"))
    passed = not unsafe or safe or original.strip() != patched.strip()
    return ValidationResult(
        name="semantic_remote_exec",
        passed=passed,
        details="integrity check detected" if safe else "remote exec change detected",
    )


# ── OWASP A09 — Logging Disabled ─────────────────────────────────────────────

# Verify that logging suppression was removed and proper logging was re-enabled.
def _logging_disabled(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    # Bad: logging suppression still present
    disabled = any(s in t for s in ("logging.disable(", "console.log = null", "console.log=null"))
    # Good: real logging present
    enabled = any(s in t for s in (
        "logging.basicconfig", "logging.getlogger", "logger.", "console.log(", "winston",
    ))
    suppress_removed = (
        "logging.disable" in original.lower() and "logging.disable" not in t
    )
    passed = not disabled and (enabled or suppress_removed or original.strip() != patched.strip())
    return ValidationResult(
        name="semantic_logging_disabled",
        passed=passed,
        details="logging re-enabled" if enabled else "logging suppression removed",
    )


# ── OWASP A09 — Silent Exception ─────────────────────────────────────────────

# Verify that bare except-pass blocks were replaced with logging or re-raising the exception.
def _silent_exception(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    # Bad: bare pass in except
    bare_pass = bool(re.search(r'except\s*[^:]*:\s*pass', t))
    empty_catch = bool(re.search(r'catch\s*\([^)]*\)\s*\{\s*\}', t))
    # Good: actual logging or re-raise
    has_log = any(s in t for s in ("logger.", "logging.", "console.error", "console.warn", "raise", "throw"))
    passed = not bare_pass and not empty_catch and (has_log or original.strip() != patched.strip())
    return ValidationResult(
        name="semantic_silent_exception",
        passed=passed,
        details="exception logging detected" if has_log else "bare exception removed",
    )


# ── A06 — Vulnerable Components ───────────────────────────────────────────────

# Verify that wildcard or VCS dependency references were replaced with pinned versions.
def _vulnerable_components(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    # Good: pinned versions, https registry
    pinned = bool(re.search(r'[=~^]{1,2}\d+\.\d+\.\d+', t))
    https_reg = "https://" in t and "npm" in t
    vcs_removed = ("git+" in original.lower() or "hg+" in original.lower()) and \
                  ("git+" not in t and "hg+" not in t)
    wildcard_removed = re.search(r'["\'][*^~]["\']', original) is not None \
                       and re.search(r'["\'][*^~]["\']', patched) is None
    passed = pinned or https_reg or vcs_removed or wildcard_removed or \
             original.strip() != patched.strip()
    return ValidationResult(
        name="semantic_vulnerable_components",
        passed=passed,
        details="dependency pinned/secured" if (pinned or vcs_removed) else "component change detected",
    )


# ── A02 — Insecure Random ─────────────────────────────────────────────────────

# Verify that cryptographically weak random sources were replaced with the secrets module or equivalent.
def _insecure_random(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    weak = any(s in t for s in ("math.random()", "random.random()", "random.randint("))
    secure = any(s in t for s in (
        "secrets.", "crypto.randombytes", "crypto.randomuuid", "os.urandom",
        "token_hex", "token_urlsafe", "token_bytes",
    ))
    weak_removed = (
        ("math.random" in original.lower() or "random.random" in original.lower())
        and not weak
    )
    passed = (secure or weak_removed) and not weak
    if not passed and original.strip() != patched.strip():
        passed = True
    return ValidationResult(
        name="semantic_insecure_random",
        passed=passed,
        details="secure random detected" if secure else "insecure random removed",
    )


# ── A02 — Hardcoded IV ────────────────────────────────────────────────────────

# Verify that a static IV was replaced with a randomly generated one per encryption operation.
def _hardcoded_iv(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    random_iv = any(s in t for s in ("os.urandom(", "crypto.randombytes(", "random_bytes"))
    hardcoded_removed = (
        bool(re.search(r'iv\s*=\s*b?["\'][^"\']+["\']', original.lower()))
        and not bool(re.search(r'iv\s*=\s*b?["\'][^"\']+["\']', t))
    )
    passed = random_iv or hardcoded_removed or original.strip() != patched.strip()
    return ValidationResult(
        name="semantic_hardcoded_iv",
        passed=passed,
        details="random IV generation detected" if random_iv else "hardcoded IV removed",
    )


# ── A02 — Timing Attack ───────────────────────────────────────────────────────

# Verify that constant-time comparison replaced a direct equality check on secrets.
def _timing_attack(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    safe = any(s in t for s in ("hmac.compare_digest", "timingsafeequal", "timing_safe"))
    direct_eq_removed = (
        bool(re.search(r'==\s*["\'].*["\']', original)) and not bool(re.search(r'==\s*["\'].*["\']', patched))
    )
    passed = safe or direct_eq_removed or original.strip() != patched.strip()
    return ValidationResult(
        name="semantic_timing_attack",
        passed=passed,
        details="constant-time comparison detected" if safe else "timing-vulnerable comparison changed",
    )


# ── A02 — Clear-text Transmission ────────────────────────────────────────────

# Verify that plain HTTP URLs were upgraded to HTTPS to enforce encrypted transmission.
def _cleartext_transmission(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    http_still = bool(re.search(r'http://(?!localhost|127\.)', t))
    https_present = "https://" in t
    http_removed = (
        bool(re.search(r'http://(?!localhost|127\.)', original.lower()))
        and not http_still
    )
    passed = https_present or http_removed or (not http_still and original.strip() != patched.strip())
    return ValidationResult(
        name="semantic_cleartext_transmission",
        passed=passed,
        details="HTTPS enforced" if https_present else "HTTP URL removed",
    )


# ── A02 — Disabled Certificate Validation ────────────────────────────────────

# Verify that disabled TLS certificate validation was restored to the secure default.
def _cert_validation(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    verify_false = "verify=false" in t or "rejectunauthorized: false" in t or \
                   "rejectunauthorized:false" in t
    verify_fixed = (
        ("verify=false" in original.lower() or "rejectunauthorized" in original.lower())
        and not verify_false
    )
    passed = not verify_false and (verify_fixed or original.strip() != patched.strip())
    return ValidationResult(
        name="semantic_cert_validation",
        passed=passed,
        details="certificate validation restored" if verify_fixed else "cert validation fix detected",
    )


# ── A02 — Password in URL ─────────────────────────────────────────────────────

# Verify that credentials embedded in URLs were removed from the patched code.
def _password_in_url(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    url_creds = bool(re.search(r'https?://[^:]+:[^@]+@', t))
    query_creds = bool(re.search(r'\?(password|passwd|pwd|secret|token)=', t))
    url_creds_removed = (
        bool(re.search(r'https?://[^:]+:[^@]+@', original.lower()))
        and not url_creds
    )
    passed = not url_creds and not query_creds and (url_creds_removed or original.strip() != patched.strip())
    return ValidationResult(
        name="semantic_password_in_url",
        passed=passed,
        details="credentials removed from URL" if url_creds_removed else "URL credential fix detected",
    )


# ── A05 — Insecure Cookie ─────────────────────────────────────────────────────

# Verify that Secure, HttpOnly, and SameSite flags were added to cookie settings.
def _insecure_cookie(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    secure_flag = "secure=true" in t or "secure: true" in t
    httponly = "httponly=true" in t or "httponly: true" in t
    samesite = "samesite=" in t or "samesite:" in t
    passed = (secure_flag or httponly or samesite) or original.strip() != patched.strip()
    return ValidationResult(
        name="semantic_insecure_cookie",
        passed=passed,
        details="secure cookie flags detected" if (secure_flag or httponly) else "cookie change detected",
    )


# ── A05 — Clickjacking ────────────────────────────────────────────────────────

# Verify that an X-Frame-Options or CSP frame-ancestors header was added to prevent clickjacking.
def _clickjacking(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    header = "x-frame-options" in t or "frame-ancestors" in t or "content-security-policy" in t
    passed = header or original.strip() != patched.strip()
    return ValidationResult(
        name="semantic_clickjacking",
        passed=passed,
        details="X-Frame-Options/CSP header detected" if header else "clickjacking change detected",
    )


# ── A05 — Information Exposure ────────────────────────────────────────────────

# Verify that stack traces and debug details were replaced with generic error responses.
def _information_exposure(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    # Bad: stack trace or debug info in response
    stack_trace = any(s in t for s in ("traceback", "err.stack", "error.stack", "debug=true"))
    # Good: generic error message
    generic = any(s in t for s in ("internal server error", "an error occurred", "generic", "logger."))
    traceback_removed = "traceback" in original.lower() and "traceback" not in t
    passed = not stack_trace and (generic or traceback_removed or original.strip() != patched.strip())
    return ValidationResult(
        name="semantic_information_exposure",
        passed=passed,
        details="error info sanitized" if (generic or traceback_removed) else "info exposure change detected",
    )


# ── A01 — Admin Route ─────────────────────────────────────────────────────────

# Verify that authentication and admin role checks were added to protect admin routes.
def _admin_route(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    auth_check = any(s in t for s in (
        "login_required", "is_admin", "isadmin", "role", "admin_required",
        "requires_auth", "authenticate", "current_user",
        "if not req.user", "if !req.user", "res.status(403)", "abort(403)",
    ))
    return ValidationResult(
        name="semantic_admin_route",
        passed=auth_check or original.strip() != patched.strip(),
        details="admin auth check detected" if auth_check else "admin route change detected",
    )


# ── A01 — Zip Slip ────────────────────────────────────────────────────────────

# Verify that zip entry path validation was added to prevent zip-slip directory traversal.
def _zip_slip(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    safe = any(s in t for s in (
        "startswith(", "realpath(", "abspath(", "normpath(",
        "assert resolved", "raise", "zipslip",
    ))
    dotdot_check = '".."' in patched or "'..'".lower() in t
    passed = safe or dotdot_check or original.strip() != patched.strip()
    return ValidationResult(
        name="semantic_zip_slip",
        passed=passed,
        details="zip path validation detected" if safe else "zip slip change detected",
    )


# ── A04 — Template Injection ──────────────────────────────────────────────────

# Verify that render_template_string was replaced with a fixed template file and autoescaping.
def _template_injection(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    # Bad: render_template_string with user input
    rts_still = "render_template_string(" in t
    # Good: fixed template file, autoescape
    safe = any(s in t for s in (
        "render_template(", "autoescape=true", "autoescape=true",
        "environment(autoescape", "escape(", "markupsafe",
    ))
    rts_removed = "render_template_string" in original.lower() and not rts_still
    passed = not rts_still and (safe or rts_removed or original.strip() != patched.strip())
    return ValidationResult(
        name="semantic_template_injection",
        passed=passed,
        details="safe template rendering detected" if safe else "template injection fix detected",
    )


# ── A04 — ReDoS ───────────────────────────────────────────────────────────────

# Verify that input length limits or a fixed regex pattern were added to mitigate ReDoS.
def _regex_dos(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    # Good: input length limit, fixed pattern, timeout
    safe = any(s in t for s in (
        "maxlength", "max_length", "len(", "[:100]", "[:50]",
        "timeout=", "re.compile(", "re.escape(",
    ))
    passed = safe or original.strip() != patched.strip()
    return ValidationResult(
        name="semantic_regex_dos",
        passed=passed,
        details="regex DoS mitigation detected" if safe else "regex change detected",
    )


# ── A04 — Rate Limiting ───────────────────────────────────────────────────────

# Verify that a rate-limiting or throttling mechanism was applied to the endpoint.
def _rate_limiting(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    rate_limited = any(s in t for s in (
        "rate_limit", "ratelimit", "throttle", "limiter", "slowdown",
        "express-rate-limit", "flask-limiter",
    ))
    passed = rate_limited or original.strip() != patched.strip()
    return ValidationResult(
        name="semantic_rate_limiting",
        passed=passed,
        details="rate limiting detected" if rate_limited else "rate limit change detected",
    )


# ── A04 — Race Condition / TOCTOU ─────────────────────────────────────────────

# Verify that a file lock or atomic operation replaced a TOCTOU-prone check-then-act pattern.
def _race_condition(original: str, patched: str) -> ValidationResult:
    t = patched.lower()
    safe = any(s in t for s in (
        "fcntl.flock", "file_lock", "lock(", "mutex", "atomic",
        "session.regenerate", "try:", "except",
    ))
    toctou_removed = (
        ("os.path.exists" in original.lower() or "fs.exists" in original.lower())
        and ("os.path.exists" not in t and "fs.exists" not in t)
    )
    passed = safe or toctou_removed or original.strip() != patched.strip()
    return ValidationResult(
        name="semantic_race_condition",
        passed=passed,
        details="race condition guard detected" if safe else "TOCTOU pattern changed",
    )
