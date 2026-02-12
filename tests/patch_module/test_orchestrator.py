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
