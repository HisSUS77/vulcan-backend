from fastapi import APIRouter, Depends
from app.api.deps import get_current_user
from app.schemas.scan import ScanStart
from app.services.scan_service import ScanService


router = APIRouter(prefix="/scans", tags=["scans"])
service = ScanService()


@router.post("/start", status_code=202)
async def start_scan(payload: ScanStart, user=Depends(get_current_user)):
    sid = service.start(payload.repo_id, payload.branch, payload.scan_mode)
    return {"scan_id": sid}


@router.get("/{scan_id}/status")
async def scan_status(scan_id: str, user=Depends(get_current_user)):
    job = service.status(scan_id)
    return {
        "state": job.get("state"),
        "progress": job.get("progress", 0),
        "eta": 0,
        "started_at": job.get("started_at"),
        "finished_at": job.get("finished_at"),
    }


@router.get("/{scan_id}/logs")
async def scan_logs(scan_id: str, user=Depends(get_current_user)):
    return service.logs(scan_id)


@router.get("/{scan_id}/summary")
async def scan_summary(scan_id: str, user=Depends(get_current_user)):
    return service.summary(scan_id) or {"detail": "Not found"}


@router.post("/{scan_id}/cancel")
async def cancel_scan(scan_id: str, user=Depends(get_current_user)):
    return service.cancel(scan_id)
