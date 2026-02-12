from __future__ import annotations

from typing import Optional


class PromptBuilder:
    """
    Build deterministic prompts for patch generation.
    Output must be unified diff only (no markdown).
    """

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
    ) -> str:
        language = (language or "python").lower()
        vuln_key = (vuln_type or "").lower()
        rules = PromptBuilder._rules_for_vuln(language, vuln_key)
        taint_repr = taint_path if isinstance(taint_path, str) else str(taint_path or "")

        context = context_before_after.strip() if context_before_after else ""
        slice_block = vulnerable_slice.strip()

        prompt = [
            "You are an automated secure code patch generator.",
            "Return ONLY a unified diff. Do not include markdown or commentary.",
            "Do not change unrelated code. Minimal safe fix only.",
            f"Language: {language}",
            f"Vulnerability: {vuln_type}",
            f"CWE: {cwe or 'N/A'}",
            f"OWASP: {owasp or 'N/A'}",
            f"Source: {source or 'unknown'}",
            f"Sink: {sink or 'unknown'}",
            "",
            "Security rules:",
            rules,
            "",
            "Vulnerable slice:",
            slice_block,
        ]
        if context:
            prompt.extend(["", "Context (before/after):", context])
        if taint_repr:
            prompt.extend(["", "Taint path:", taint_repr])
        prompt.extend([
            "",
            "Output format rules:",
            "- Must start with '--- ' and '+++ ' lines.",
            "- Must include @@ hunks.",
            "- Only modify the vulnerable file shown in the slice.",
            "- Do not add new dependencies.",
        ])
        return "\n".join(prompt).strip() + "\n"

    @staticmethod
    def _rules_for_vuln(language: str, vuln_key: str) -> str:
        lang = "python" if language.startswith("py") else "javascript"
        rules = {
            "sqli": {
                "python": (
                    "Use parameterized queries. Do not build SQL strings with user input. "
                    "Prefer cursor.execute(sql, params) with placeholders ('?' or '%s')."
                ),
                "javascript": (
                    "Use parameterized queries or query builders (knex/sequelize). "
                    "Do not concatenate user input into SQL strings."
                ),
            },
            "xss": {
                "python": (
                    "Escape output or use safe templating. "
                    "Never render raw user input without escaping."
                ),
                "javascript": (
                    "Avoid innerHTML for untrusted data or sanitize with DOMPurify. "
                    "Use textContent or safe templating."
                ),
            },
            "commandinjection": {
                "python": (
                    "Use subprocess.run([...], shell=False). "
                    "Avoid os.system or shell=True. Validate/allowlist inputs."
                ),
                "javascript": (
                    "Use child_process.execFile or spawn with args array. "
                    "Avoid exec with string concatenation; validate/allowlist inputs."
                ),
            },
            "pathtraversal": {
                "python": (
                    "Normalize and validate paths (os.path.abspath) and enforce allowlists. "
                    "Reject path segments with '..'."
                ),
                "javascript": (
                    "Use path.resolve and enforce allowlists. "
                    "Reject path traversal sequences."
                ),
            },
            "idor": {
                "python": (
                    "Enforce ownership checks or authorization before accessing resource IDs."
                ),
                "javascript": (
                    "Enforce ownership checks or authorization before accessing resource IDs."
                ),
            },
        }

        for key, rule in rules.items():
            if key in vuln_key:
                return rule.get(lang, rule.get("python", "Apply secure coding best practices."))
        return "Apply secure coding best practices for this vulnerability type."
