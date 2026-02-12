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

    def __init__(self) -> None:
        self.timeout = int(os.getenv("PATCH_LLM_TIMEOUT", "20"))
        self.max_tokens = int(os.getenv("PATCH_LLM_MAX_TOKENS", "1200"))
        self.retries = int(os.getenv("PATCH_LLM_RETRIES", "1"))
        self.primary_model = os.getenv("PATCH_LLM_MODEL", "gpt-4o")
        self.github_model = os.getenv("PATCH_LLM_GITHUB_MODEL", "gpt-4o-mini")
        self._llm_service = LLMService(provider="openai", model=self.primary_model)

    async def generate_patch(self, prompt: str) -> str:
        """
        Generate unified diff patch from prompt.
        Returns diff-only text or a fallback template if no LLM available.
        """
        response = await self._try_openai(prompt)
        if response:
            return self._clean_output(response)

        response = await self._try_github(prompt)
        if response:
            return self._clean_output(response)

        logger.warning("No LLM available; returning offline template patch")
        return self._offline_template_diff()

    async def _try_openai(self, prompt: str) -> Optional[str]:
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
            return await self._call_client(prompt)
        except Exception as exc:
            logger.error(f"OpenAI patch generation failed: {exc}")
            return None

    async def _try_github(self, prompt: str) -> Optional[str]:
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
            return await self._call_client(prompt)
        except Exception as exc:
            logger.error(f"GitHub Models patch generation failed: {exc}")
            return None

    async def _call_client(self, prompt: str) -> str:
        if not self._llm_service.client:
            raise RuntimeError("LLM client not initialized")

        async def _call():
            return await self._llm_service.client.chat.completions.create(
                model=self._llm_service.model,
                messages=[
                    {"role": "system", "content": "You are a secure code patch generator."},
                    {"role": "user", "content": prompt},
                ],
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
