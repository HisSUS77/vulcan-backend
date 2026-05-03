"""
PatchLLMService — LLM wrapper for patch generation (patch role).

Delegates all provider management to RoleAwareLLMPool('patch'):

  DeepSeek-V3  →  gpt-4o  →  Llama-4-Maverick  →  Groq DeepSeek-R1  →  OpenAI gpt-4o

Low-volume role: runs once per approved patch request, so uses the best
available coding models — quality and correctness over speed.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
from typing import Optional

from semantic_engine.classifier.llm_pool import RoleAwareLLMPool
from app.patch_module.diff_utils import normalize_diff_text

logger = logging.getLogger(__name__)


class PatchLLMService:
    """
    LLM patch generation service.

    All generation methods share the same pool; the system message is varied
    per method to direct the model toward different output formats.
    """

    # ── System prompts ────────────────────────────────────────────────────────

    _SYS_DIFF = (
        "You are a precision secure-code patch generator. "
        "Output ONLY valid unified diff text. "
        "Never output markdown code fences, prose, or explanation. "
        "The diff must start with '--- a/<file>' and '+++ b/<file>' lines "
        "followed by @@ hunk headers. "
        "Make the minimal change required to fix the vulnerability. "
        "Preserve all indentation and surrounding code exactly."
    )

    _SYS_REASONING = (
        "You are a Principal Security Engineer with deep expertise in application security, "
        "secure code review, and vulnerability remediation. "
        "You conduct thorough, adversarial security analyses following a formal protocol. "
        "Output ONLY structured plain-text analysis — no diffs, no code blocks, no markdown."
    )

    _SYS_DIFF_FROM_SPEC = (
        "You are a precision patch generator. "
        "You receive a security analysis with an embedded PATCH_SPEC block. "
        "Your only job is to faithfully translate that PATCH_SPEC into a valid unified diff. "
        "Change ONLY the lines listed as REMOVE in PATCH_SPEC. "
        "Replace them with exactly the ADD lines from PATCH_SPEC. "
        "Output ONLY the unified diff — no prose, no markdown, no code fences."
    )

    _SYS_ATTACK_TESTER = (
        "You are a senior penetration tester simulating attacks against security patches. "
        "Output ONLY a structured ATTACK_TEST_BEGIN...ATTACK_TEST_END block. "
        "No prose. No markdown. No explanations outside the block."
    )

    # Initialize the patch LLM service, configuring timeout, token limit, and the role-aware provider pool.
    def __init__(self) -> None:
        self.timeout    = int(os.getenv("PATCH_LLM_TIMEOUT", "90"))
        self.max_tokens = int(os.getenv("PATCH_LLM_MAX_TOKENS", "4000"))
        self._pool = RoleAwareLLMPool(
            role="patch",
            timeout=self.timeout,
            min_interval_ms=int(os.getenv("PATCH_LLM_MIN_INTERVAL_MS", "3000")),
        )

    # ── Public generation API ─────────────────────────────────────────────────

    async def generate_patch(self, prompt: str) -> str:
        """Generate a unified diff patch directly from prompt."""
        raw = await self._call(self._SYS_DIFF, [{"role": "user", "content": prompt}])
        return self._clean_diff(raw) if raw else self._offline_diff()

    async def generate_patch_with_cot(self, reasoning_prompt: str, diff_prompt: str) -> str:
        """
        Legacy 2-step CoT — kept for fallback compatibility.
        Prefer generate_patch_with_industrial_cot() for new calls.
        """
        reasoning = await self._call(self._SYS_REASONING, [{"role": "user", "content": reasoning_prompt}])
        if not reasoning:
            logger.warning("CoT reasoning step failed; falling back to direct generation")
            return await self.generate_patch(diff_prompt)

        logger.debug("CoT reasoning complete (%d chars)", len(reasoning))
        raw = await self._call(self._SYS_DIFF, [
            {"role": "user",      "content": reasoning_prompt},
            {"role": "assistant", "content": reasoning},
            {"role": "user",      "content": diff_prompt},
        ])
        return self._clean_diff(raw) if raw else self._offline_diff()

    async def generate_patch_with_industrial_cot(
        self,
        industrial_reasoning_prompt: str,
        diff_prompt: str,
    ) -> str:
        """
        Industrial-grade 4-phase CoT:
          Phase 1: Threat modeling (attack surface, exploit, CVSS estimate)
          Phase 2: Fix design     (secure pattern, minimal change spec)
          Phase 3: Adversarial verification (attacker tries to bypass own fix)
          Phase 4: Formal PATCH_SPEC (structured contract for diff generator)

        Call 2 reads the PATCH_SPEC block and translates it to a unified diff.
        Fall-back chain: industrial → legacy CoT → direct → offline template.
        """
        # ── Call 1: 4-phase adversarial security analysis ─────────────────────
        analysis = await self._call(
            self._SYS_REASONING,
            [{"role": "user", "content": industrial_reasoning_prompt}],
        )
        if not analysis:
            logger.warning("Industrial CoT analysis failed; falling back to legacy CoT")
            return await self.generate_patch_with_cot(industrial_reasoning_prompt, diff_prompt)

        logger.debug(
            "Industrial CoT analysis complete (%d chars, PATCH_SPEC=%s)",
            len(analysis), "PATCH_SPEC_BEGIN" in analysis,
        )

        # ── Call 2: translate PATCH_SPEC → unified diff ───────────────────────
        diff_from_spec = (
            "The security analysis above contains a PATCH_SPEC_BEGIN...PATCH_SPEC_END block.\n"
            "Translate that specification into a valid unified diff.\n"
            "Rules:\n"
            "  1. REMOVE only the lines listed as REMOVE[N] in the spec.\n"
            "  2. ADD exactly the lines listed as ADD[N] in the spec.\n"
            "  3. Add any NEW_IMPORT lines at the correct position.\n"
            "  4. Preserve all surrounding context lines exactly (use ' ' prefix).\n"
            "  5. Emit correct @@ hunk line numbers.\n"
            "  6. Start output with:  --- a/<FILE from spec>\n"
            "YOUR ONLY OUTPUT IS A VALID UNIFIED DIFF. NO PROSE. NO CODE FENCES."
        )
        raw = await self._call(self._SYS_DIFF_FROM_SPEC, [
            {"role": "user",      "content": industrial_reasoning_prompt},
            {"role": "assistant", "content": analysis},
            {"role": "user",      "content": diff_from_spec},
        ])
        if raw:
            return self._clean_diff(raw)

        # Last resort: direct generation
        logger.warning("Industrial CoT diff call failed; attempting direct fallback")
        raw = await self._call(self._SYS_DIFF, [{"role": "user", "content": diff_prompt}])
        return self._clean_diff(raw) if raw else self._offline_diff()

    async def test_patch_against_attacks(self, attack_prompt: str) -> Optional["AttackTestResult"]:
        """
        Adversarial patch attack simulation — runs after patch generation.
        Returns None if no LLM available (non-blocking; patch still usable).
        """
        raw = await self._call(
            self._SYS_ATTACK_TESTER,
            [{"role": "user", "content": attack_prompt}],
        )
        if not raw:
            logger.warning("Attack test LLM call failed — skipping attack simulation")
            return None
        logger.debug("Attack test response received (%d chars)", len(raw))
        return self._parse_attack_test(raw)

    # ── Internal call helper ──────────────────────────────────────────────────

    async def _call(self, system: str, user_messages: list) -> Optional[str]:
        """Route a call through the patch pool with the given system prompt."""
        messages = [{"role": "system", "content": system}] + user_messages
        return await self._pool.call(messages=messages, max_tokens=self.max_tokens, temperature=0.0)

    # ── Output helpers ────────────────────────────────────────────────────────

    # Normalize and strip surrounding whitespace from raw LLM diff output.
    def _clean_diff(self, text: str) -> str:
        return normalize_diff_text(text).strip()

    # Return a placeholder unified diff when no LLM provider is reachable.
    def _offline_diff(self) -> str:
        logger.warning("No LLM available — returning offline template patch")
        return "\n".join([
            "--- a/PLACEHOLDER_FILE",
            "+++ b/PLACEHOLDER_FILE",
            "@@ -1,1 +1,1 @@",
            "-# TODO: vulnerable code",
            "+# TODO: apply secure fix (LLM unavailable)",
        ])

    # ── Attack test parser ────────────────────────────────────────────────────

    def _parse_attack_test(self, raw: str) -> Optional["AttackTestResult"]:
        from app.patch_module.models import AttackTestResult, AttackAttempt
        try:
            m     = re.search(r"ATTACK_TEST_BEGIN(.*?)ATTACK_TEST_END", raw, re.DOTALL)
            block = m.group(1).strip() if m else raw

            attacks = []
            for i in range(1, 6):
                name_m   = re.search(rf"ATTACK\[{i}\]\.NAME:\s*(.+)", block)
                result_m = re.search(rf"ATTACK\[{i}\]\.RESULT:\s*(BLOCKED|BYPASSED)", block, re.IGNORECASE)
                reason_m = re.search(rf"ATTACK\[{i}\]\.REASON:\s*(.+)", block)
                if not (name_m and result_m):
                    continue
                attacks.append(AttackAttempt(
                    name=name_m.group(1).strip(),
                    technique=name_m.group(1).strip(),
                    result=result_m.group(1).strip().upper(),
                    explanation=reason_m.group(1).strip() if reason_m else "",
                ))

            overall_m = re.search(r"OVERALL:\s*(SECURE|VULNERABLE)", block, re.IGNORECASE)
            conf_m    = re.search(r"PATCH_CONFIDENCE:\s*(\d+)", block)
            rec_m     = re.search(r"RECOMMENDATION:\s*(.+)", block)

            overall_secure   = (overall_m.group(1).upper() == "SECURE") if overall_m else True
            patch_confidence = int(conf_m.group(1)) if conf_m else 75
            recommendation   = rec_m.group(1).strip() if rec_m else "No additional recommendations."

            if any(a.result == "BYPASSED" for a in attacks):
                overall_secure = False

            return AttackTestResult(
                overall_secure=overall_secure,
                patch_confidence=patch_confidence,
                attacks=attacks,
                recommendation=recommendation,
                raw_analysis=raw,
            )
        except Exception as exc:
            logger.error("Attack test parse failed: %s", exc)
            return None
