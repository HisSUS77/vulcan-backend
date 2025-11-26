from fastapi import APIRouter, Depends
from app.api.deps import get_current_user
from app.schemas.patch import PatchGenerate
from app.services.patch_service import PatchService


router = APIRouter(prefix="/patches", tags=["patches"])
service = PatchService()


@router.get("/{scan_id}/vulnerabilities")
async def list_patchable(scan_id: str, user=Depends(get_current_user)):
    return service.list_vulnerabilities(scan_id)


@router.post("/generate", status_code=201)
async def generate(payload: PatchGenerate, user=Depends(get_current_user)):
    return service.generate(payload.vulnerability_id, payload.options)


@router.get("/{patch_id}")
async def get_patch(patch_id: int, user=Depends(get_current_user)):
    return service.get(patch_id) or {"detail": "Not found"}


@router.post("/{patch_id}/apply")
async def apply_patch(patch_id: int, user=Depends(get_current_user)):
    return service.apply(patch_id)


@router.post("/{patch_id}/export")
async def export_patch(patch_id: int, user=Depends(get_current_user)):
    return service.export(patch_id)


@router.post("/{patch_id}/regenerate")
async def regenerate_patch(patch_id: int, user=Depends(get_current_user)):
    return service.regenerate(patch_id)
