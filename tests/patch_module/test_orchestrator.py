import pytest

from app.patch_module.orchestrator import PatchOrchestrator
from app.patch_module.models import VulnerabilityContext
from tests.patch_module._fake_db import FakeDB


@pytest.mark.asyncio
async def test_orchestrator_generate_with_context(monkeypatch):
    db = FakeDB()
    orchestrator = PatchOrchestrator(db)

    original = "def cmd_exec(host):\n    os.system(\"ping -c 1 \" + host)"
    diff = "\n".join([
        "--- a/app.py",
        "+++ b/app.py",
        "@@ -1,2 +1,2 @@",
        "-def cmd_exec(host):",
        "-    os.system(\"ping -c 1 \" + host)",
        "+def cmd_exec(host):",
        "+    subprocess.run([\"ping\", \"-c\", \"1\", host], shell=False)",
    ])

    async def fake_generate_patch(prompt):
        return diff

    monkeypatch.setattr(orchestrator.llm, "generate_patch", fake_generate_patch)

    ctx = VulnerabilityContext(
        vulnerability_id="v-1",
        file_path="app.py",
        language="python",
        vuln_type="Command Injection",
        cwe="CWE-78",
        owasp="A03",
        vulnerable_slice=original,
        context_before_after=None,
        taint_path=["source", "sink"],
        sink="os.system",
        source="host",
    )

    response = await orchestrator.generate(user_id="u-1", vulnerability_id=None, context=ctx)
    assert response.patch_id
    assert response.unified_diff.startswith("--- ")
    assert response.status in {"generated", "rejected"}

    patch = await orchestrator.repo.get_patch(response.patch_id)
    assert patch is not None


@pytest.mark.asyncio
async def test_orchestrator_uses_cot_on_first_attempt(monkeypatch):
    """First attempt must use generate_patch_with_cot; retries use generate_patch."""
    db = FakeDB()
    orchestrator = PatchOrchestrator(db)

    diff = "\n".join([
        "--- a/app.py",
        "+++ b/app.py",
        "@@ -1,2 +1,2 @@",
        "-    os.system(\"ping -c 1 \" + host)",
        "+    subprocess.run([\"ping\", \"-c\", \"1\", host], shell=False)",
    ])

    cot_calls = []
    direct_calls = []

    async def fake_generate_patch_with_cot(industrial_reasoning_prompt, diff_prompt):
        cot_calls.append((industrial_reasoning_prompt, diff_prompt))
        return diff

    async def fake_generate_patch(prompt):
        direct_calls.append(prompt)
        return diff

    monkeypatch.setattr(orchestrator.llm, "generate_patch_with_industrial_cot", fake_generate_patch_with_cot)
    monkeypatch.setattr(orchestrator.llm, "generate_patch", fake_generate_patch)

    ctx = VulnerabilityContext(
        vulnerability_id="v-2",
        file_path="app.py",
        language="python",
        vuln_type="Command Injection",
        cwe="CWE-78",
        owasp="A03",
        vulnerable_slice='os.system("ping -c 1 " + host)',
        context_before_after=None,
        taint_path=["host", "os.system"],
        sink="os.system",
        source="host",
    )

    response = await orchestrator.generate(user_id="u-1", vulnerability_id=None, context=ctx)

    # Industrial CoT must have been called exactly once (first attempt)
    assert len(cot_calls) == 1
    # Direct generate_patch must NOT be called (confidence goal met on first try)
    assert len(direct_calls) == 0
    assert response.generation_attempts == 1
    assert response.unified_diff.startswith("--- ")


@pytest.mark.asyncio
async def test_orchestrator_retries_use_direct_generate(monkeypatch):
    """When CoT produces a failing diff, retries use generate_patch (critique path)."""
    db = FakeDB()
    orchestrator = PatchOrchestrator(db)

    bad_diff = "not a valid diff at all"
    good_diff = "\n".join([
        "--- a/app.py",
        "+++ b/app.py",
        "@@ -1,1 +1,1 @@",
        "-    os.system(cmd)",
        "+    subprocess.run([cmd], shell=False)",
    ])

    cot_calls = []
    direct_calls = []

    async def fake_generate_patch_with_cot(industrial_reasoning_prompt, diff_prompt):
        cot_calls.append(1)
        return bad_diff  # attempt 0 fails validation

    async def fake_generate_patch(prompt):
        direct_calls.append(1)
        return good_diff  # retry succeeds

    monkeypatch.setattr(orchestrator.llm, "generate_patch_with_industrial_cot", fake_generate_patch_with_cot)
    monkeypatch.setattr(orchestrator.llm, "generate_patch", fake_generate_patch)

    ctx = VulnerabilityContext(
        vulnerability_id="v-3",
        file_path="app.py",
        language="python",
        vuln_type="Command Injection",
        cwe="CWE-78",
        owasp="A03",
        vulnerable_slice="os.system(cmd)",
        context_before_after=None,
        taint_path=None,
        sink="os.system",
        source="cmd",
    )

    response = await orchestrator.generate(user_id="u-1", vulnerability_id=None, context=ctx)

    assert len(cot_calls) == 1       # Industrial CoT tried once (attempt 0)
    assert len(direct_calls) >= 1    # at least one retry used direct generate
    assert response.generation_attempts >= 2
