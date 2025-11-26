from fastapi import APIRouter, Depends
from app.api.deps import get_current_user
from app.services.report_service import ReportService


router = APIRouter(prefix="/reports", tags=["reports"])
service = ReportService()


@router.get("")
async def list_reports(repo_id: int | None = None, date_from: str | None = None, date_to: str | None = None, tag: str | None = None, user=Depends(get_current_user)):
    return service.list(repo_id, date_from, date_to, tag)


@router.get("/{report_id}")
async def get_report(report_id: int, user=Depends(get_current_user)):
    return service.get(report_id)


@router.get("/{report_id}/export")
async def export_report(report_id: int, format: str = "json", user=Depends(get_current_user)):
    return service.export(report_id, format)


@router.post("/compare")
async def compare_reports(payload: dict, user=Depends(get_current_user)):
    return service.compare(payload.get("report_id_1"), payload.get("report_id_2"))
