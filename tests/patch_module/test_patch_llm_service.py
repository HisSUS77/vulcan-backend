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

    async def fake_try_openai(messages):
        return ""

    async def fake_try_github(messages):
        return ""

    monkeypatch.setattr(service, "_try_openai", fake_try_openai)
    monkeypatch.setattr(service, "_try_github", fake_try_github)

    result = await service.generate_patch("prompt")
    assert "PLACEHOLDER_FILE" in result


# ── CoT tests ─────────────────────────────────────────────────────────────────

VALID_DIFF = "\n".join([
    "--- a/app.py",
    "+++ b/app.py",
    "@@ -1,2 +1,2 @@",
    '-    os.system("ping " + host)',
    '+    subprocess.run(["ping", host], shell=False)',
])


@pytest.mark.asyncio
async def test_generate_patch_with_cot_success(monkeypatch):
    """Both reasoning and diff steps succeed — returns cleaned diff."""
    service = PatchLLMService()
    calls = []

    async def fake_try_openai(messages):
        calls.append(messages)
        if len(calls) == 1:
            # reasoning step — return prose
            return "Root cause: os.system with user input. Fix: use subprocess list form."
        # diff step — return a valid diff
        return VALID_DIFF

    monkeypatch.setattr(service, "_try_openai", fake_try_openai)

    result = await service.generate_patch_with_cot("reasoning prompt", "diff prompt")

    assert len(calls) == 2
    # First call uses reasoning system message (allows prose)
    assert calls[0][0]["content"] == service._SYSTEM_REASONING
    # Second call uses strict diff system message
    assert calls[1][0]["content"] == service._SYSTEM
    # Second call injects reasoning as prior assistant turn
    assert calls[1][2]["role"] == "assistant"
    assert "subprocess" in calls[1][2]["content"]
    # Output is a clean diff
    assert result.startswith("--- ")


@pytest.mark.asyncio
async def test_generate_patch_with_cot_reasoning_fails_fallback(monkeypatch):
    """If reasoning step returns empty, falls back to direct generate_patch."""
    service = PatchLLMService()

    async def fake_try_openai(messages):
        return ""

    async def fake_try_github(messages):
        return ""

    fallback_called = []

    async def fake_generate_patch(prompt):
        fallback_called.append(prompt)
        return VALID_DIFF

    monkeypatch.setattr(service, "_try_openai", fake_try_openai)
    monkeypatch.setattr(service, "_try_github", fake_try_github)
    monkeypatch.setattr(service, "generate_patch", fake_generate_patch)

    result = await service.generate_patch_with_cot("reasoning prompt", "diff prompt")

    assert fallback_called == ["diff prompt"]
    assert result.startswith("--- ")


@pytest.mark.asyncio
async def test_generate_patch_with_cot_diff_step_fails(monkeypatch):
    """Reasoning succeeds but diff step returns empty — returns offline template."""
    service = PatchLLMService()
    call_count = [0]

    async def fake_try_openai(messages):
        call_count[0] += 1
        if call_count[0] == 1:
            return "Root cause: user input reaches os.system."
        return ""  # diff step fails

    async def fake_try_github(messages):
        return ""

    monkeypatch.setattr(service, "_try_openai", fake_try_openai)
    monkeypatch.setattr(service, "_try_github", fake_try_github)

    result = await service.generate_patch_with_cot("reasoning prompt", "diff prompt")

    assert "PLACEHOLDER_FILE" in result


@pytest.mark.asyncio
async def test_generate_patch_with_cot_reasoning_in_diff_context(monkeypatch):
    """Verifies reasoning text is passed as the assistant turn in the diff call."""
    service = PatchLLMService()
    diff_call_messages = []
    call_count = [0]

    async def fake_try_openai(messages):
        call_count[0] += 1
        if call_count[0] == 1:
            return "REASONING: use subprocess list form."
        diff_call_messages.extend(messages)
        return VALID_DIFF

    monkeypatch.setattr(service, "_try_openai", fake_try_openai)

    await service.generate_patch_with_cot("reasoning prompt", "diff prompt")

    roles = [m["role"] for m in diff_call_messages]
    assert roles == ["system", "user", "assistant", "user"]
    # The assistant turn must contain the reasoning text
    assistant_turn = next(m for m in diff_call_messages if m["role"] == "assistant")
    assert "REASONING" in assistant_turn["content"]
    # Final user turn is the diff prompt
    last_user = [m for m in diff_call_messages if m["role"] == "user"][-1]
    assert last_user["content"] == "diff prompt"
