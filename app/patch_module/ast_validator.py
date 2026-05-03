"""
AST-level Python security validator.

String-matching catches surface patterns. AST analysis catches the same
issues regardless of whitespace, aliased imports, or multi-line expressions.
This is the approach used by Bandit, Semgrep (pattern-matching on AST nodes),
and CodeQL (structural queries over the AST/CFG).

We run this IN ADDITION TO the string-matching semantic validators — the two
complement each other:
  - String-matching: fast, catches JS and Python, works on partial diffs
  - AST: precise, catches aliased imports / complex expressions, Python only
"""
from __future__ import annotations

import ast
import textwrap
from typing import List, Optional

from app.patch_module.models import ValidationResult


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse(code: str) -> Optional[ast.Module]:
    """
    Try to parse a code snippet into an AST, handling indented fragments
    (e.g. code inside a function body that was extracted as the vulnerable slice).
    """
    for transform in (
        lambda c: c,
        textwrap.dedent,
        lambda c: "def _():\n" + textwrap.indent(textwrap.dedent(c), "    "),
    ):
        try:
            return ast.parse(transform(code))
        except SyntaxError:
            continue
    return None


def _attr_name(node: ast.expr) -> str:
    """Return 'module.attr' for Attribute nodes, bare name for Name nodes."""
    if isinstance(node, ast.Attribute):
        return f"{_attr_name(node.value)}.{node.attr}"
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _kw(node: ast.Call, name: str) -> Optional[ast.expr]:
    """Return the value of a keyword argument by name, or None."""
    for kw in node.keywords:
        if kw.arg == name:
            return kw.value
    return None


# Return True if the AST node is the boolean constant True.
def _is_true(node: Optional[ast.expr]) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


# Return True if the AST node is the boolean constant False.
def _is_false(node: Optional[ast.expr]) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


# ── Visitor ───────────────────────────────────────────────────────────────────

class _SecurityVisitor(ast.NodeVisitor):
    """
    Walks the AST and records security issues found in the patched code.
    Each check is independent — a single Call node may trigger multiple checks.
    """

    # Initialize the visitor with an empty issues list to accumulate findings.
    def __init__(self) -> None:
        self.issues: List[str] = []

    # ── Call-level checks ─────────────────────────────────────────────────────

    # Dispatch all call-level security checks for every function call node in the AST.
    def visit_Call(self, node: ast.Call) -> None:
        name = _attr_name(node.func)
        self._check_subprocess_shell_true(node, name)
        self._check_os_system(name, node)
        self._check_eval_exec(node, name)
        self._check_sql_string_concat(node, name)
        self._check_pickle(name, node)
        self._check_yaml_unsafe(name, node)
        self._check_requests_verify_false(name, node)
        self.generic_visit(node)

    def _check_subprocess_shell_true(self, node: ast.Call, name: str) -> None:
        _SUBPROCESS_FUNCS = {
            "subprocess.run", "subprocess.call", "subprocess.Popen",
            "subprocess.check_call", "subprocess.check_output",
        }
        if name in _SUBPROCESS_FUNCS:
            shell_val = _kw(node, "shell")
            if _is_true(shell_val):
                self.issues.append(
                    f"[AST] {name}() called with shell=True at line {node.lineno} "
                    f"— use shell=False and a list of arguments"
                )

    # Flag direct os.system or os.popen calls which allow shell injection.
    def _check_os_system(self, name: str, node: ast.Call) -> None:
        if name in ("os.system", "os.popen"):
            self.issues.append(
                f"[AST] {name}() at line {node.lineno} — "
                f"replace with subprocess.run([...], shell=False)"
            )

    # Flag eval, exec, and compile calls that execute arbitrary code strings.
    def _check_eval_exec(self, node: ast.Call, name: str) -> None:
        if name in ("eval", "exec", "compile"):
            self.issues.append(
                f"[AST] {name}() at line {node.lineno} — "
                f"remove eval/exec; use ast.literal_eval() or a dispatch dict"
            )

    def _check_sql_string_concat(self, node: ast.Call, name: str) -> None:
        """Detect cursor.execute(<BinOp or JoinedStr>) — string-built SQL."""
        if not name.endswith(".execute"):
            return
        if not node.args:
            return
        first_arg = node.args[0]
        # BinOp: "SELECT " + user_input
        # JoinedStr: f"SELECT {user_input}"
        if isinstance(first_arg, (ast.BinOp, ast.JoinedStr)):
            self.issues.append(
                f"[AST] cursor.execute() with string concatenation/interpolation "
                f"at line {node.lineno} — use parameterized query with placeholders"
            )

    # Flag pickle.loads and pickle.load calls that deserialize untrusted data unsafely.
    def _check_pickle(self, name: str, node: ast.Call) -> None:
        if name in ("pickle.loads", "pickle.load"):
            self.issues.append(
                f"[AST] {name}() at line {node.lineno} — "
                f"never deserialize untrusted data with pickle; use json.loads()"
            )

    # Flag yaml.load without SafeLoader and yaml.unsafe_load as insecure deserialization.
    def _check_yaml_unsafe(self, name: str, node: ast.Call) -> None:
        if name == "yaml.load":
            # yaml.load(data) without Loader=yaml.SafeLoader is unsafe
            loader = _kw(node, "Loader")
            if loader is None or _attr_name(loader) not in ("yaml.SafeLoader", "SafeLoader"):
                self.issues.append(
                    f"[AST] yaml.load() without SafeLoader at line {node.lineno} "
                    f"— use yaml.safe_load() instead"
                )
        if name == "yaml.unsafe_load":
            self.issues.append(
                f"[AST] yaml.unsafe_load() at line {node.lineno} "
                f"— replace with yaml.safe_load()"
            )

    # Flag requests calls with verify=False that disable TLS certificate validation.
    def _check_requests_verify_false(self, name: str, node: ast.Call) -> None:
        _REQUEST_FUNCS = {
            "requests.get", "requests.post", "requests.put",
            "requests.delete", "requests.patch", "requests.request",
            "session.get", "session.post",
        }
        if name in _REQUEST_FUNCS:
            verify = _kw(node, "verify")
            if _is_false(verify):
                self.issues.append(
                    f"[AST] {name}() with verify=False at line {node.lineno} "
                    f"— always validate TLS certificates (remove verify=False)"
                )

    # ── Assignment-level checks ────────────────────────────────────────────────

    # Dispatch assignment-level security checks for every assignment node in the AST.
    def visit_Assign(self, node: ast.Assign) -> None:
        self._check_hardcoded_secret(node)
        self.generic_visit(node)

    def _check_hardcoded_secret(self, node: ast.Assign) -> None:
        """Detect SECRET_KEY = 'hardcoded' style assignments."""
        _SECRET_NAMES = {"password", "secret", "secret_key", "api_key", "token",
                         "passwd", "private_key", "access_token"}
        if not isinstance(node.value, ast.Constant):
            return
        val = node.value.value
        if not isinstance(val, str) or len(val) < 4:
            return
        for target in node.targets:
            var_name = (_attr_name(target) or "").lower().replace("_", "")
            if any(s.replace("_", "") in var_name for s in _SECRET_NAMES):
                self.issues.append(
                    f"[AST] Hardcoded secret in variable '{_attr_name(target)}' "
                    f"at line {node.lineno} — use os.getenv() or a secrets manager"
                )


# ── Public API ────────────────────────────────────────────────────────────────

def validate_python_ast(patched_code: str) -> List[ValidationResult]:
    """
    Run AST-level security analysis on the patched Python code.
    Returns [] if the code cannot be parsed (syntax validator handles that case).
    Returns a single ValidationResult summarising all findings.
    """
    tree = _parse(patched_code)
    if tree is None:
        return []  # Syntax validator already handles unparseable code

    visitor = _SecurityVisitor()
    visitor.visit(tree)

    if not visitor.issues:
        return [ValidationResult(
            name="ast_python",
            passed=True,
            details="No dangerous AST patterns detected in patched code",
        )]

    return [ValidationResult(
        name="ast_python",
        passed=False,
        details="; ".join(visitor.issues),
    )]
