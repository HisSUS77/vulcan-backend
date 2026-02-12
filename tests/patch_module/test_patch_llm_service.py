import pytest

from app.patch_module.patch_llm_service import PatchLLMService


@pytest.mark.asyncio
async def test_generate_patch_valid_diff(monkeypatch):
    service = PatchLLMService()
    diff_text = "```diff\n--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-foo\n+bar\n```"

    async def fake_try_openai(prompt):
        return diff_text

    async def fake_try_github(prompt):
        return None

    monkeypatch.setattr(service, "_try_openai", fake_try_openai)
    monkeypatch.setattr(service, "_try_github", fake_try_github)

    result = await service.generate_patch("prompt")
    assert result.startswith("--- ")
    assert "```" not in result


@pytest.mark.asyncio
async def test_generate_patch_invalid_diff(monkeypatch):
    service = PatchLLMService()
    bad_text = "this is not a diff"

    async def fake_try_openai(prompt):
        return bad_text

    async def fake_try_github(prompt):
        return None

    monkeypatch.setattr(service, "_try_openai", fake_try_openai)
    monkeypatch.setattr(service, "_try_github", fake_try_github)

    result = await service.generate_patch("prompt")
    assert result == bad_text


@pytest.mark.asyncio
async def test_generate_patch_empty_fallback(monkeypatch):
    service = PatchLLMService()

    async def fake_try_openai(prompt):
        return ""

    async def fake_try_github(prompt):
        return ""

    monkeypatch.setattr(service, "_try_openai", fake_try_openai)
    monkeypatch.setattr(service, "_try_github", fake_try_github)

    result = await service.generate_patch("prompt")
    assert "PLACEHOLDER_FILE" in result
