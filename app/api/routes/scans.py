from fastapi import APIRouter, Depends, HTTPException
from app.api.deps import get_current_user
from app.schemas.scan import ScanStart, ScanResponse, ScanStatusRead, ScanSummary
from app.services.scan_service import get_scan_service
from datetime import datetime


router = APIRouter(prefix="/scans", tags=["scans"])
service = get_scan_service()  # Use singleton instance


@router.post("/start", status_code=202, response_model=ScanResponse)
async def start_scan(payload: ScanStart, user=Depends(get_current_user)):
    """
    Start a vulnerability scan with dual input modes:
    
    **Direct Code Scan:**
    - Provide `code`, `language`, and optionally `filename`
    - Code limited to 400 lines
    - Immediate analysis of provided code
    
    **Repository Scan:**
    - Provide `repo_id` and `branch`
    - Scans all .py/.js/.ts files in repository
    - Processes files one by one
    
    Returns scan_id for polling progress.
    """
    try:
        scan_id, input_type = service.start(
            code=payload.code,
            language=payload.language.value if payload.language else None,
            filename=payload.filename,
            repo_id=payload.repo_id,
            branch=payload.branch,
            scan_mode=payload.scan_mode.value
        )
        
        return ScanResponse(
            scan_id=scan_id,
            status="PENDING",
            message="Scan initiated successfully",
            input_type=input_type,
            created_at=datetime.utcnow().isoformat()
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to start scan: {str(e)}"
        )


@router.get("/{scan_id}/status", response_model=ScanStatusRead)
async def scan_status(scan_id: str, user=Depends(get_current_user)):
    """
    Get current scan status with progress information.
    
    Returns:
    - state: PENDING, RUNNING, COMPLETED, FAILED, CANCELLED
    - progress: 0-100
    - current_file: Currently scanning file (for repo scans)
    - files_scanned/total_files: File progress counters
    """
    job = service.status(scan_id)
    
    if job.get("state") == "NOT_FOUND":
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return ScanStatusRead(
        state=job["state"],
        progress=job["progress"],
        eta=None,  # Can calculate ETA based on progress
        started_at=job.get("started_at"),
        finished_at=job.get("finished_at"),
        current_file=job.get("current_file"),
        files_scanned=job.get("files_scanned", 0),
        total_files=job.get("total_files", 0)
    )


@router.get("/{scan_id}/logs")
async def scan_logs(scan_id: str, user=Depends(get_current_user)):
    """
    Get real-time scan logs.
    Returns last 100 log entries.
    """
    return service.logs(scan_id)


@router.get("/{scan_id}/summary", response_model=ScanSummary)
async def scan_summary(scan_id: str, user=Depends(get_current_user)):
    """
    Get final scan summary with vulnerability results.
    
    Available after scan completes.
    Includes:
    - Total files scanned
    - Vulnerabilities found
    - Severity breakdown
    - Full vulnerability details
    """
    summary = service.summary(scan_id)
    
    if not summary:
        raise HTTPException(status_code=404, detail="Scan not found or not completed")
    
    return ScanSummary(**summary)


@router.post("/{scan_id}/cancel")
async def cancel_scan(scan_id: str, user=Depends(get_current_user)):
    """
    Cancel a running scan.
    """
    result = service.cancel(scan_id)
    
    if result.get("state") == "NOT_FOUND":
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return {"scan_id": scan_id, "status": "CANCELLED"}
