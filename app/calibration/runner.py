"""
Patch Calibration Runner
========================
Runs patch generation against the known-vulnerable test corpus (vuln-test-repo-25)
and computes actual accuracy per vulnerability type and per confidence tier.

Usage (from repo root):
    python -m app.calibration.runner

What it does:
  1. Reads vuln_app.py and vuln_app.js from the test repo
  2. For each vulnerability type that Vulcan can detect, creates a mock
     VulnerabilityContext using the relevant code slice
  3. Generates a patch (without LLM — uses validation only in dry-run mode,
     OR with LLM when --live flag is set)
  4. Records: tier, confidence, structural pass, semantic pass
  5. Prints a calibration table: predicted confidence vs actual semantic pass rate

This is the empirical calibration step that production security tools
(Semgrep, CodeQL) use to set their confidence tier boundaries.

Flags:
  --live        Actually call the LLM (slow, uses API quota)
  --dry-run     Skip LLM; use the vulnerable code as a mock "patch" (tests validators)
  --vuln-type X Only run for one vulnerability type
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

# ── Ensure the project root is on the path ────────────────────────────────────
_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))

from app.patch_module.models import VulnerabilityContext, ValidationResult
from app.patch_module.patch_validator import PatchValidator
from app.patch_module.orchestrator import PatchOrchestrator

# ── Test corpus ───────────────────────────────────────────────────────────────
_REPO_PATH = _ROOT / "vuln-test-repo-25"

# Each entry: (vuln_type, language, file, code_slice, expected_fix_description)
# The code_slice is the vulnerable fragment that will become VulnerabilityContext.vulnerable_slice
_CORPUS: List[tuple] = [
    # (vuln_type, lang, filename, slice, cwe, owasp)
    (
        "SQL Injection", "python", "vuln_app.py",
        'query = "SELECT * FROM users WHERE name = \'" + username + "\'"',
        "CWE-89", "A03",
    ),
    (
        "Command Injection", "python", "vuln_app.py",
        'os.system("ping " + user_input)',
        "CWE-78", "A03",
    ),
    (
        "XSS", "javascript", "vuln_app.js",
        'element.innerHTML = userInput;',
        "CWE-79", "A03",
    ),
    (
        "Path Traversal", "python", "vuln_app.py",
        'open(base_dir + "/" + user_path)',
        "CWE-22", "A01",
    ),
    (
        "Insecure Deserialization", "python", "vuln_app.py",
        'data = pickle.loads(user_bytes)',
        "CWE-502", "A08",
    ),
    (
        "Hardcoded Secrets", "python", "vuln_app.py",
        'SECRET_KEY = "hardcoded-secret-123"',
        "CWE-798", "A07",
    ),
    (
        "Weak Crypto", "python", "vuln_app.py",
        'hashlib.md5(password.encode()).hexdigest()',
        "CWE-327", "A02",
    ),
    (
        "SSRF", "python", "vuln_app.py",
        'requests.get(user_supplied_url)',
        "CWE-918", "A10",
    ),
    (
        "JWT None Algorithm", "python", "vuln_app.py",
        'jwt.decode(token, secret, algorithms=["none", "HS256"])',
        "CWE-347", "A07",
    ),
    (
        "Insecure Cookie", "python", "vuln_app.py",
        'response.set_cookie("session", session_id)',
        "CWE-614", "A05",
    ),
    (
        "CORS Misconfiguration", "python", "vuln_app.py",
        'CORS(app, origins="*")',
        "CWE-942", "A05",
    ),
    (
        "Debug Mode Enabled", "python", "vuln_app.py",
        'app.run(debug=True)',
        "CWE-94", "A05",
    ),
    (
        "Insecure Random", "python", "vuln_app.py",
        'token = str(random.random())',
        "CWE-338", "A02",
    ),
    (
        "Template Injection", "python", "vuln_app.py",
        'render_template_string(user_template)',
        "CWE-94", "A03",
    ),
    (
        "Silent Exception", "python", "vuln_app.py",
        'try:\n    do_something()\nexcept:\n    pass',
        "CWE-390", "A09",
    ),
]


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class CalibrationResult:
    vuln_type: str
    language: str
    confidence: float
    label: str
    structural_score: float
    semantic_score: float
    generation_attempts: int
    validations: List[ValidationResult] = field(default_factory=list)
    error: Optional[str] = None


# ── Runner ────────────────────────────────────────────────────────────────────

class CalibrationRunner:

    def __init__(self, live: bool = False) -> None:
        self.live = live
        self.validator = PatchValidator()
        # Lazy orchestrator (no DB in calibration mode)
        self._orch = PatchOrchestrator.__new__(PatchOrchestrator)

    def _make_ctx(self, entry: tuple) -> VulnerabilityContext:
        vuln_type, lang, fname, slice_, cwe, owasp = entry
        return VulnerabilityContext(
            vulnerability_id=None,
            file_path=fname,
            language=lang,
            vuln_type=vuln_type,
            cwe=cwe,
            owasp=owasp,
            vulnerable_slice=textwrap.dedent(slice_),
            context_before_after=None,
            taint_path=None,
            sink=None,
            source=None,
        )

    async def _generate_or_mock(self, ctx: VulnerabilityContext) -> str:
        """Return a real LLM patch (live mode) or mock patch (dry-run)."""
        if not self.live:
            # Dry-run: return the vulnerable slice as the "patch" so we can
            # measure how validators behave against known-bad code.
            # Useful for calibrating validator sensitivity.
            lines = ctx.vulnerable_slice.splitlines()
            hunk = "\n".join(f"-{l}" for l in lines)
            return (
                f"--- a/{ctx.file_path}\n"
                f"+++ b/{ctx.file_path}\n"
                f"@@ -1,{len(lines)} +1,0 @@\n"
                f"{hunk}\n"
            )

        # Live mode — actually call the LLM
        from app.patch_module.prompt_builder import PromptBuilder
        from app.patch_module.patch_llm_service import PatchLLMService
        llm = PatchLLMService()
        prompt = PromptBuilder.build_prompt(
            language=ctx.language,
            vuln_type=ctx.vuln_type,
            cwe=ctx.cwe,
            owasp=ctx.owasp,
            vulnerable_slice=ctx.vulnerable_slice,
            context_before_after=None,
            taint_path=None,
            sink=None,
            source=None,
            file_path=ctx.file_path,
        )
        return await llm.generate_patch(prompt)

    async def run_one(self, entry: tuple) -> CalibrationResult:
        vuln_type = entry[0]
        lang = entry[1]
        ctx = self._make_ctx(entry)
        try:
            diff = await self._generate_or_mock(ctx)
            validations = self.validator.validate(ctx, diff)
            confidence = self._orch._compute_confidence(diff, validations)
            breakdown = self._orch._compute_score_breakdown(validations, confidence, 1)
            return CalibrationResult(
                vuln_type=vuln_type,
                language=lang,
                confidence=confidence,
                label=breakdown["label"],
                structural_score=breakdown["structural"],
                semantic_score=breakdown["semantic"],
                generation_attempts=1,
                validations=validations,
            )
        except Exception as exc:
            return CalibrationResult(
                vuln_type=vuln_type,
                language=lang,
                confidence=0.0,
                label="ERROR",
                structural_score=0.0,
                semantic_score=0.0,
                generation_attempts=0,
                error=str(exc),
            )

    async def run_all(self, filter_type: Optional[str] = None) -> List[CalibrationResult]:
        corpus = _CORPUS
        if filter_type:
            corpus = [e for e in corpus if filter_type.lower() in e[0].lower()]
        tasks = [self.run_one(entry) for entry in corpus]
        return await asyncio.gather(*tasks)


# ── Reporting ─────────────────────────────────────────────────────────────────

def _print_table(results: List[CalibrationResult]) -> None:
    # Group by label tier
    tiers = {"HIGH": [], "MEDIUM": [], "LOW": [], "UNVERIFIED": [], "ERROR": []}
    for r in results:
        tiers.setdefault(r.label, []).append(r)

    print()
    print("=" * 90)
    print("  VULCAN PATCH CALIBRATION REPORT")
    print("=" * 90)
    print(f"  {'Vulnerability Type':<32} {'Lang':<6} {'Tier':<12} {'Struct':>7} {'Seman':>7} {'Overall':>8}")
    print("-" * 90)

    for r in sorted(results, key=lambda x: -x.confidence):
        marker = "⚠" if r.error else ""
        print(
            f"  {r.vuln_type:<32} {r.language:<6} {r.label:<12} "
            f"{r.structural_score:>6.0%} {r.semantic_score:>6.0%} {r.confidence:>7.0%}  {marker}"
        )
        if r.error:
            print(f"    ERROR: {r.error}")

    print("-" * 90)

    # Per-tier summary
    print()
    print("  TIER SUMMARY")
    print(f"  {'Tier':<12} {'Count':>6} {'Avg Structural':>15} {'Avg Semantic':>13} {'Avg Overall':>12}")
    print("-" * 62)
    for tier_name in ("HIGH", "MEDIUM", "LOW", "UNVERIFIED", "ERROR"):
        group = tiers.get(tier_name, [])
        if not group:
            continue
        avg_struct = sum(r.structural_score for r in group) / len(group)
        avg_sem    = sum(r.semantic_score    for r in group) / len(group)
        avg_conf   = sum(r.confidence        for r in group) / len(group)
        print(f"  {tier_name:<12} {len(group):>6} {avg_struct:>14.0%} {avg_sem:>12.0%} {avg_conf:>11.0%}")

    print("=" * 90)
    print()
    print("  Calibration insight:")
    print("  * If HIGH-tier patches have low semantic scores  -> tighten tier boundary")
    print("  * If MEDIUM-tier patches always pass semantic    -> raise lower bound")
    print("  * If a vuln type consistently lands in LOW       -> review its semantic validator")
    print()


# ── Entry point ───────────────────────────────────────────────────────────────

async def main() -> None:
    parser = argparse.ArgumentParser(description="Vulcan patch calibration runner")
    parser.add_argument("--live", action="store_true",
                        help="Call the LLM for real patches (uses API quota)")
    parser.add_argument("--vuln-type", default=None,
                        help="Only run for vulnerability types matching this string")
    args = parser.parse_args()

    mode = "LIVE (LLM)" if args.live else "DRY-RUN (mock diffs)"
    print(f"\n  Running calibration in {mode} mode...")

    runner = CalibrationRunner(live=args.live)
    results = await runner.run_all(filter_type=args.vuln_type)
    _print_table(results)


if __name__ == "__main__":
    asyncio.run(main())
