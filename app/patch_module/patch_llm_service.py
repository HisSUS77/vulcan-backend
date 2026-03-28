from __future__ import annotations

import asyncio
import os
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

    # Reasoning system message — allows prose for chain-of-thought analysis step.
    _SYSTEM_REASONING = (
        "You are a secure code review expert. "
        "Analyze vulnerabilities step by step with precision. "
        "Output only structured reasoning text — no diffs, no code blocks, no markdown."
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
        Two-step chain-of-thought patch generation.

        Step 1 — Reasoning: ask the model to analyze the vulnerability (root cause,
                 attack vector, affected lines, secure replacement). Output is prose.
        Step 2 — Diff: feed the reasoning back as prior assistant context, then ask
                 for the unified diff. The model has already "thought" about the fix,
                 so the diff is more precise and minimal.

        Falls back to direct generation if the reasoning step fails.
        """
        # ── Step 1: reasoning ──────────────────────────────────────────────────
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

        # ── Step 2: diff with reasoning as prior context ───────────────────────
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
