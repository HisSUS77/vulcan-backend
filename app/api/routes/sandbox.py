from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.api.deps import get_current_user
from app.db.mongo import get_mongo_db
from app.services.sandbox_service import SandboxService

router = APIRouter(prefix="/sandbox", tags=["sandbox"])


class SandboxRunRequest(BaseModel):
    poc_code:  str
    language:  str = "python"
    vuln_type: str = "unknown"


@router.post("/run")
async def run_sandbox(
    payload: SandboxRunRequest,
    user=Depends(get_current_user),
):
    """
    Execute PoC exploit code in an isolated Docker container.
    Returns real stdout/stderr and whether the exploit was confirmed.
    """
    if not payload.poc_code or not payload.poc_code.strip():
        raise HTTPException(status_code=400, detail="poc_code is required")
    if len(payload.poc_code) > 8000:
        raise HTTPException(status_code=400, detail="poc_code exceeds 8000 char limit")

    svc = SandboxService()
    result = await svc.run(
        poc_code=payload.poc_code,
        language=payload.language,
        vuln_type=payload.vuln_type,
    )
    return {
        "confirmed":  result.confirmed,
        "stdout":     result.stdout,
        "stderr":     result.stderr,
        "exit_code":  result.exit_code,
        "timed_out":  result.timed_out,
        "error":      result.error,
        "status":     "CONFIRMED" if result.confirmed else ("TIMEOUT" if result.timed_out else "NOT_CONFIRMED"),
    }


class AttackTestRequest(BaseModel):
    patch_id:         str
    attack_name:      str   # e.g. "Direct Payload"
    attack_technique: str   # e.g. "SQL Injection - Direct Payload"


@router.post("/attack-test")
async def run_attack_test(
    payload: AttackTestRequest,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """
    Generate a self-contained attack test for a specific attack vector and
    run it in the sandbox against the patched code.

    The LLM writes a stdlib-only Python script that embeds the patched function
    inline and uses in-memory resources (sqlite3, tempfile) so it never needs
    network access — unlike a generic PoC that connects to real services.
    """
    from app.patch_module.patch_repository import PatchRepository
    from app.patch_module.orchestrator import PatchOrchestrator

    repo = PatchRepository(db)
    patch = await repo.get_patch(payload.patch_id)
    if not patch:
        raise HTTPException(status_code=404, detail="Patch not found")

    original_code = patch.get("vulnerable_slice", "")
    unified_diff  = patch.get("unified_diff", "")
    vuln_type     = patch.get("vuln_type", "unknown")

    # Apply the diff to get the patched code
    patched_code = PatchOrchestrator._apply_diff_to_code(original_code, unified_diff)
    if not patched_code or not patched_code.strip():
        patched_code = original_code  # fallback: use original if diff failed

    svc = SandboxService()
    result = await svc.generate_attack_test(
        patched_code=patched_code,
        vuln_type=vuln_type,
        attack_name=payload.attack_name,
        attack_technique=payload.attack_technique,
    )

    verdict = "BLOCKED" if result.exit_code == 0 else ("TIMEOUT" if result.timed_out else "BYPASSED")
    return {
        "confirmed":  result.confirmed,
        "stdout":     result.stdout,
        "stderr":     result.stderr,
        "exit_code":  result.exit_code,
        "timed_out":  result.timed_out,
        "error":      result.error,
        "verdict":    verdict,
        "attack_name": payload.attack_name,
    }


@router.get("/available")
async def sandbox_available(user=Depends(get_current_user)):
    """Check if Docker sandbox is available on this host."""
    available = SandboxService.is_docker_available()
    return {"available": available, "message": "Docker sandbox ready" if available else "Docker not available"}
