from __future__ import annotations

import asyncio
import os
import re
import logging
from typing import Optional

from semantic_engine.classifier.llm_service import LLMService
from app.patch_module.diff_utils import normalize_diff_text

logger = logging.getLogger(__name__)


class PatchLLMService:
    """
    LLM wrapper for patch generation.
    Uses existing LLMService for provider initialization, but sends patch prompts.
    """

    # Strict system message — instructs the model to output ONLY valid unified diffs.
    _SYSTEM = (
        "You are a precision secure-code patch generator. "
        "You output ONLY valid unified diff text. "
        "Never output markdown code fences, prose, or explanation. "
        "The diff must start with '--- a/<file>' and '+++ b/<file>' lines "
        "followed by @@ hunk headers. "
        "Make the minimal change required to fix the vulnerability. "
        "Preserve all indentation and surrounding code exactly."
    )

    # Reasoning system — allows structured prose for multi-phase security analysis.
    _SYSTEM_REASONING = (
        "You are a Principal Security Engineer with deep expertise in application security, "
        "secure code review, and vulnerability remediation. "
        "You conduct thorough, adversarial security analyses following a formal protocol. "
        "Output ONLY structured plain-text analysis — no diffs, no code blocks, no markdown."
    )

    # Diff-from-spec system — diff generator that reads a formal PATCH_SPEC.
    _SYSTEM_DIFF_FROM_SPEC = (
        "You are a precision patch generator. "
        "You receive a security analysis with an embedded PATCH_SPEC block. "
        "Your only job is to faithfully translate that PATCH_SPEC into a valid unified diff. "
        "Change ONLY the lines listed as REMOVE in PATCH_SPEC. "
        "Replace them with exactly the ADD lines from PATCH_SPEC. "
        "Output ONLY the unified diff — no prose, no markdown, no code fences."
    )

    def __init__(self) -> None:
        self.timeout = int(os.getenv("PATCH_LLM_TIMEOUT", "45"))
        self.max_tokens = int(os.getenv("PATCH_LLM_MAX_TOKENS", "2400"))
        self.retries = int(os.getenv("PATCH_LLM_RETRIES", "2"))
        self.primary_model = os.getenv("PATCH_LLM_MODEL", "gpt-4o")
        self.github_model = os.getenv("PATCH_LLM_GITHUB_MODEL", "gpt-4o")
        self._llm_service = LLMService(provider="openai", model=self.primary_model)

    async def generate_patch(self, prompt: str) -> str:
        """
        Generate unified diff patch from prompt.
        Returns diff-only text or a fallback template if no LLM available.
        """
        messages = [
            {"role": "system", "content": self._SYSTEM},
            {"role": "user", "content": prompt},
        ]
        response = await self._try_openai(messages)
        if response:
            return self._clean_output(response)

        response = await self._try_github(messages)
        if response:
            return self._clean_output(response)

        logger.warning("No LLM available; returning offline template patch")
        return self._offline_template_diff()

    async def generate_patch_with_cot(self, reasoning_prompt: str, diff_prompt: str) -> str:
        """
        Legacy 2-step CoT — kept for fallback compatibility.
        Prefer generate_patch_with_industrial_cot() for new calls.
        """
        reasoning_messages = [
            {"role": "system", "content": self._SYSTEM_REASONING},
            {"role": "user", "content": reasoning_prompt},
        ]
        reasoning = await self._try_openai(reasoning_messages)
        if not reasoning:
            reasoning = await self._try_github(reasoning_messages)
        if not reasoning:
            logger.warning("CoT reasoning step failed; falling back to direct generation")
            return await self.generate_patch(diff_prompt)

        logger.debug("CoT reasoning complete (%d chars)", len(reasoning))

        diff_messages = [
            {"role": "system", "content": self._SYSTEM},
            {"role": "user", "content": reasoning_prompt},
            {"role": "assistant", "content": reasoning},
            {"role": "user", "content": diff_prompt},
        ]
        response = await self._try_openai(diff_messages)
        if response:
            return self._clean_output(response)
        response = await self._try_github(diff_messages)
        if response:
            return self._clean_output(response)
        logger.warning("CoT diff step failed; returning offline template")
        return self._offline_template_diff()

    async def generate_patch_with_industrial_cot(
        self,
        industrial_reasoning_prompt: str,
        diff_prompt: str,
    ) -> str:
        """
        Industrial-grade 2-call Chain-of-Thought patch generation.

        CALL 1 — Multi-phase adversarial security analysis:
          Phase 1: Threat modeling  (attack surface, exploit, CVSS estimate)
          Phase 2: Fix design       (secure pattern, minimal change spec, import analysis)
          Phase 3: Adversarial verification (attacker tries to bypass their own fix)
          Phase 4: Formal PATCH_SPEC (structured contract for the diff generator)

        CALL 2 — Diff-from-spec generation:
          The model receives the full Phase 1-4 analysis as prior assistant context.
          It reads the embedded PATCH_SPEC block and translates it into a unified diff.
          Because the spec was adversarially verified in Phase 3, the diff is precise
          and addresses edge-case bypasses that a simple CoT would miss.

        Fall-back chain: industrial → legacy CoT → direct → offline template.
        """
        # ── CALL 1: 4-phase adversarial security analysis ──────────────────────
        analysis_messages = [
            {"role": "system", "content": self._SYSTEM_REASONING},
            {"role": "user",   "content": industrial_reasoning_prompt},
        ]
        analysis = await self._try_openai(analysis_messages)
        if not analysis:
            analysis = await self._try_github(analysis_messages)

        if not analysis:
            logger.warning("Industrial CoT analysis call failed; falling back to legacy CoT")
            return await self.generate_patch_with_cot(industrial_reasoning_prompt, diff_prompt)

        logger.debug(
            "Industrial CoT analysis complete (%d chars, PATCH_SPEC present=%s)",
            len(analysis),
            "PATCH_SPEC_BEGIN" in analysis,
        )

        # ── CALL 2: translate PATCH_SPEC → unified diff ────────────────────────
        diff_from_spec_prompt = (
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
        diff_messages = [
            {"role": "system",    "content": self._SYSTEM_DIFF_FROM_SPEC},
            {"role": "user",      "content": industrial_reasoning_prompt},
            {"role": "assistant", "content": analysis},
            {"role": "user",      "content": diff_from_spec_prompt},
        ]
        response = await self._try_openai(diff_messages)
        if response:
            return self._clean_output(response)

        response = await self._try_github(diff_messages)
        if response:
            return self._clean_output(response)

        # Fall back: try legacy CoT with the analysis text as context
        logger.warning("Industrial CoT diff call failed; attempting legacy CoT fallback")
        diff_messages_fallback = [
            {"role": "system",    "content": self._SYSTEM},
            {"role": "user",      "content": diff_prompt},
        ]
        response = await self._try_openai(diff_messages_fallback)
        if response:
            return self._clean_output(response)
        response = await self._try_github(diff_messages_fallback)
        if response:
            return self._clean_output(response)

        return self._offline_template_diff()

    # ── Attack tester system message ──────────────────────────────────────────
    _SYSTEM_ATTACK_TESTER = (
        "You are a senior penetration tester simulating attacks against security patches. "
        "Output ONLY a structured ATTACK_TEST_BEGIN...ATTACK_TEST_END block. "
        "No prose. No markdown. No explanations outside the block."
    )

    async def test_patch_against_attacks(self, attack_prompt: str) -> Optional["AttackTestResult"]:
        """
        Adversarial patch attack simulation — runs after patch generation.

        Sends the generated diff + original vulnerable code to a new LLM call
        that plays the role of a penetration tester trying 5 specific bypass
        techniques. Parses the structured ATTACK_TEST_BEGIN...END output and
        returns an AttackTestResult.

        Returns None if no LLM is available (non-blocking — patch still usable).
        """
        # Import here to avoid circular imports
        from app.patch_module.models import AttackTestResult, AttackAttempt

        messages = [
            {"role": "system", "content": self._SYSTEM_ATTACK_TESTER},
            {"role": "user",   "content": attack_prompt},
        ]
        raw = await self._try_openai(messages)
        if not raw:
            raw = await self._try_github(messages)
        if not raw:
            logger.warning("Attack test LLM call failed — skipping attack simulation")
            return None

        logger.debug("Attack test response received (%d chars)", len(raw))
        return self._parse_attack_test(raw)

    def _parse_attack_test(self, raw: str) -> Optional["AttackTestResult"]:
        """Parse ATTACK_TEST_BEGIN...END block into AttackTestResult."""
        from app.patch_module.models import AttackTestResult, AttackAttempt

        try:
            # Extract block
            block_match = re.search(
                r"ATTACK_TEST_BEGIN(.*?)ATTACK_TEST_END", raw, re.DOTALL
            )
            block = block_match.group(1).strip() if block_match else raw

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

            overall_m  = re.search(r"OVERALL:\s*(SECURE|VULNERABLE)", block, re.IGNORECASE)
            conf_m     = re.search(r"PATCH_CONFIDENCE:\s*(\d+)", block)
            rec_m      = re.search(r"RECOMMENDATION:\s*(.+)", block)

            overall_secure   = (overall_m.group(1).upper() == "SECURE") if overall_m else True
            patch_confidence = int(conf_m.group(1)) if conf_m else 75
            recommendation   = rec_m.group(1).strip() if rec_m else "No additional recommendations."

            # If any attack bypassed, override overall to VULNERABLE
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

    async def _try_openai(self, messages: list) -> Optional[str]:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            return None
        try:
            self._llm_service._init_client({
                "provider": "openai",
                "api_key": api_key,
                "model": self.primary_model,
                "base_url": None,
            })
            return await self._call_client(messages)
        except Exception as exc:
            logger.error(f"OpenAI patch generation failed: {exc}")
            return None

    async def _try_github(self, messages: list) -> Optional[str]:
        api_key = os.getenv("LLM_API_KEY")
        if not api_key:
            return None
        base_url = os.getenv("LLM_BASE_URL", "https://models.github.ai/inference")
        try:
            self._llm_service._init_client({
                "provider": "github",
                "api_key": api_key,
                "model": self.github_model,
                "base_url": base_url,
            })
            return await self._call_client(messages)
        except Exception as exc:
            logger.error(f"GitHub Models patch generation failed: {exc}")
            return None

    async def _call_client(self, messages: list) -> str:
        if not self._llm_service.client:
            raise RuntimeError("LLM client not initialized")

        async def _call():
            return await self._llm_service.client.chat.completions.create(
                model=self._llm_service.model,
                messages=messages,
                temperature=0.0,
                max_tokens=self.max_tokens,
            )

        last_exc = None
        for _ in range(self.retries + 1):
            try:
                response = await asyncio.wait_for(_call(), timeout=self.timeout)
                return response.choices[0].message.content or ""
            except Exception as exc:
                last_exc = exc
        raise last_exc or RuntimeError("LLM call failed")

    def _clean_output(self, text: str) -> str:
        """
        Strip extra text and ensure diff-only output.
        """
        cleaned = normalize_diff_text(text)
        return cleaned.strip()

    def _offline_template_diff(self) -> str:
        """
        Offline fallback diff (placeholder) when no LLM is available.
        """
        return "\n".join([
            "--- a/PLACEHOLDER_FILE",
            "+++ b/PLACEHOLDER_FILE",
            "@@ -1,1 +1,1 @@",
            "-# TODO: vulnerable code",
            "+# TODO: apply secure fix (LLM unavailable)",
        ])
