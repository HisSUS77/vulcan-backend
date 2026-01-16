from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse, Response
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.api.deps import get_current_user
from app.db.mongo import get_mongo_db
from app.services.report_service import ReportService
from io import BytesIO


router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("")
async def list_reports(
    repo_id: int | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    tag: str | None = None,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """List all completed scan reports"""
    service = ReportService(db)
    return await service.list(user, repo_id, date_from, date_to, tag)


@router.get("/{scan_id}")
async def get_report(
    scan_id: str,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """Get detailed report for a specific scan"""
    service = ReportService(db)
    report = await service.get(scan_id, user)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.get("/{scan_id}/export")
async def export_report(
    scan_id: str,
    format: str = "json",
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """
    Export report in specified format.
    
    Formats:
    - json: Return JSON data (default)
    - csv: Return CSV file
    - pdf: Return PDF file
    """
    if format.lower() == "pdf":
        service = ReportService(db)
        pdf_content = await service.export_pdf(scan_id, user)
        if not pdf_content:
            raise HTTPException(
                status_code=404, 
                detail="Report not found or PDF generation failed"
            )
        
        return StreamingResponse(
            BytesIO(pdf_content),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=report-{scan_id}.pdf"
            }
        )
    
    elif format.lower() == "csv":
        service = ReportService(db)
        csv_content = await service.export_csv(scan_id, user)
        if not csv_content:
            raise HTTPException(
                status_code=404,
                detail="Report not found or no data available"
            )
        
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=report-{scan_id}.csv"
            }
        )
    
    elif format.lower() == "json":
        service = ReportService(db)
        report = await service.get(scan_id, user)
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        return report
    
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported format: {format}. Use 'json', 'csv', or 'pdf'."
        )


@router.post("/compare")
async def compare_reports(
    payload: dict,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """Compare two scan reports"""
    scan_id_1 = payload.get("report_id_1") or payload.get("scan_id_1")
    scan_id_2 = payload.get("report_id_2") or payload.get("scan_id_2")
    
    if not scan_id_1 or not scan_id_2:
        raise HTTPException(
            status_code=400,
            detail="Both scan_id_1 and scan_id_2 are required"
        )
    
    service = ReportService(db)
    return await service.compare(scan_id_1, scan_id_2, user)
