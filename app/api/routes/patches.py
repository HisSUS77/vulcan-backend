from fastapi import APIRouter, Depends, HTTPException, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import get_current_user
from app.core.exceptions import ValidationException, RateLimitException, ResourceNotFoundException
from app.core.permissions import require_role
from app.enums.role import UserRole
from app.db.mongo import get_mongo_db
from app.patch_module.models import (
    PatchGenerateRequest,
    PatchGenerateResponse,
    PatchValidateResponse,
    PatchApplyResponse,
    PatchExportResponse,
    PatchReviewResponse,
    PatchHistoryItem,
)
from typing import List
from app.patch_module.orchestrator import PatchOrchestrator


router = APIRouter(prefix="/patches", tags=["patches"])


@router.post("/generate", response_model=PatchGenerateResponse, status_code=201)
async def generate_patch(
    payload: PatchGenerateRequest,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """
    Generate patch from vulnerability_id or full context.

    Example request:
    {
      "vulnerability_id": "vuln-123"
    }

    Example response:
    {
      "patch_id": "b1b2c3d4",
      "unified_diff": "--- a/app.py\\n+++ b/app.py\\n@@ -1 +1 @@\\n-foo\\n+bar",
      "explanation": "Automated patch generation...",
      "confidence": 0.8,
      "validations": [{"name": "diff_format", "passed": true, "details": "1 added"}],
      "status": "generated"
    }
    """
    if not payload.vulnerability_id and not payload.context:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="vulnerability_id or context is required",
        )
    orchestrator = PatchOrchestrator(db)
    try:
        return await orchestrator.generate(user_id=user["id"], vulnerability_id=payload.vulnerability_id, context=payload.context)
    except ValidationException as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    except RateLimitException as exc:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc))
    except ResourceNotFoundException as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.post("/{patch_id}/validate", response_model=PatchValidateResponse)
async def validate_patch(
    patch_id: str,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    orchestrator = PatchOrchestrator(db)
    try:
        return await orchestrator.validate(patch_id)
    except ResourceNotFoundException as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.post("/{patch_id}/apply", response_model=PatchApplyResponse)
@require_role(UserRole.PREMIUM, UserRole.ADMIN)
async def apply_patch(
    patch_id: str,
    repo_id: str | None = None,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    orchestrator = PatchOrchestrator(db)
    try:
        return await orchestrator.apply(patch_id, user_id=user["id"], repo_id=repo_id)
    except ResourceNotFoundException as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get("/{patch_id}/export", response_model=PatchExportResponse)
@require_role(UserRole.PREMIUM, UserRole.ADMIN)
async def export_patch(
    patch_id: str,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    orchestrator = PatchOrchestrator(db)
    try:
        content = await orchestrator.export(patch_id)
        return PatchExportResponse(
            patch_id=patch_id,
            filename=f"patch-{patch_id}.patch",
            content=content,
        )
    except ResourceNotFoundException as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.post("/{patch_id}/approve", response_model=PatchReviewResponse)
@require_role(UserRole.PREMIUM, UserRole.ADMIN)
async def approve_patch(
    patch_id: str,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """FR-M6.10: Approve a patch for deployment."""
    orchestrator = PatchOrchestrator(db)
    try:
        return await orchestrator.approve(patch_id, user_id=user["id"])
    except ResourceNotFoundException as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.post("/{patch_id}/reject", response_model=PatchReviewResponse)
@require_role(UserRole.PREMIUM, UserRole.ADMIN)
async def reject_patch(
    patch_id: str,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """FR-M6.10: Reject a patch before deployment."""
    orchestrator = PatchOrchestrator(db)
    try:
        return await orchestrator.reject(patch_id, user_id=user["id"])
    except ResourceNotFoundException as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.post("/{patch_id}/verify")
async def verify_patch(
    patch_id: str,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """
    Re-scan the patched code to confirm the vulnerability is actually fixed.
    Returns: {fixed, original_vuln_type, remaining_vulns, new_vulns, verified_at}
    """
    orchestrator = PatchOrchestrator(db)
    try:
        return await orchestrator.verify(patch_id, user_id=user["id"])
    except ResourceNotFoundException as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get("/vulnerability/{vulnerability_id}/history", response_model=List[PatchHistoryItem])
async def patch_history(
    vulnerability_id: str,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """FE-5: Historical patch records for audit and traceability."""
    orchestrator = PatchOrchestrator(db)
    try:
        return await orchestrator.list_for_vulnerability(vulnerability_id)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))
