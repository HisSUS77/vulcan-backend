from fastapi import APIRouter, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.api.deps import get_current_user
from app.db.mongo import get_mongo_db
from app.enums.role import UserRole
from app.schemas.scan import ScanStart, ScanResponse, ScanStatusRead, ScanSummary
from app.services.scan_service import ScanService
from app.core.permissions import can_access_resource
from app.core.exceptions import AuthorizationException, ResourceNotFoundException
from datetime import datetime


router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("/start", status_code=202, response_model=ScanResponse)
async def start_scan(
    payload: ScanStart,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """
    Start a vulnerability scan with dual input modes.
    
    **Direct Code Scan:**
    - Provide `code`, `language`, and optionally `filename`
    - Code limited to 400 lines
    - Immediate analysis of provided code
    
    **Repository Scan:**
    - Provide `repo_id` and `branch`
    - Scans all .py/.js/.ts files in repository
    - Processes files one by one
    
    Returns scan_id for polling progress.
    
    Accessible to: All authenticated users (admin, premium, normal)
    """
    try:
        service = ScanService(db)
        scan_id, input_type = await service.start(
            user_id=user["id"],
            code=payload.code,
            language=payload.language.value if payload.language else None,
            filename=payload.filename,
            repo_id=payload.repo_id,
            branch=payload.branch,
            scan_mode=payload.scan_mode.value
        )
        
        return ScanResponse(
            scan_id=scan_id,
            user_id=user["id"],
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
async def scan_status(
    scan_id: str,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """
    Get current scan status with progress information.
    
    Returns:
    - state: PENDING, RUNNING, COMPLETED, FAILED, CANCELLED
    - progress: 0-100
    - current_file: Currently scanning file (for repo scans)
    - files_scanned/total_files: File progress counters
    
    Accessible to: Scan owner or Admin
    """
    try:
        scan = await db.scans.find_one({"scan_id": scan_id})
        if not scan:
            raise ResourceNotFoundException(f"Scan {scan_id} not found")
        
        # Check ownership: allow if user is admin or owns the scan
        if not can_access_resource(user, str(scan.get("user_id"))):
            raise AuthorizationException(f"Not authorized to access scan {scan_id}")
        
        service = ScanService(db)
        status = await service.status(scan_id)
        
        if status.state == "NOT_FOUND":
            raise ResourceNotFoundException(f"Scan {scan_id} not found")
        
        # Ensure user_id is included in response
        status_dict = status.dict() if hasattr(status, 'dict') else status
        status_dict['user_id'] = str(scan.get("user_id"))
        return ScanStatusRead(**status_dict)
    except (ResourceNotFoundException, AuthorizationException) as e:
        raise e.to_http_exception()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get scan status: {str(e)}")


@router.get("/{scan_id}/logs")
async def scan_logs(
    scan_id: str,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """
    Get real-time scan logs.
    Returns last 100 log entries.
    
    Accessible to: Scan owner or Admin
    """
    try:
        scan = await db.scans.find_one({"scan_id": scan_id})
        if not scan:
            raise ResourceNotFoundException(f"Scan {scan_id} not found")
        
        if not can_access_resource(user, str(scan.get("user_id"))):
            raise AuthorizationException(f"Not authorized to access scan {scan_id}")
        
        service = ScanService(db)
        return await service.logs(scan_id)
    except (ResourceNotFoundException, AuthorizationException) as e:
        raise e.to_http_exception()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get scan logs: {str(e)}")


@router.get("/{scan_id}/summary", response_model=ScanSummary)
async def scan_summary(
    scan_id: str,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """
    Get final scan summary with vulnerability results.
    
    Available after scan completes.
    Includes:
    - Total files scanned
    - Vulnerabilities found
    - Severity breakdown
    - Full vulnerability details
    
    Accessible to: Scan owner or Admin
    """
    try:
        scan = await db.scans.find_one({"scan_id": scan_id})
        if not scan:
            raise ResourceNotFoundException(f"Scan {scan_id} not found")
        
        if not can_access_resource(user, str(scan.get("user_id"))):
            raise AuthorizationException(f"Not authorized to access scan {scan_id}")
        
        service = ScanService(db)
        summary = await service.summary(scan_id)
        
        if not summary:
            raise ResourceNotFoundException(f"Scan {scan_id} not found or not completed")
        
        # Ensure user_id is included in response
        summary_dict = summary.dict() if hasattr(summary, 'dict') else summary
        summary_dict['user_id'] = str(scan.get("user_id"))
        return ScanSummary(**summary_dict)
    except (ResourceNotFoundException, AuthorizationException) as e:
        raise e.to_http_exception()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get scan summary: {str(e)}")


@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """
    Cancel a running scan.
    
    Accessible to: Scan owner or Admin
    """
    try:
        scan = await db.scans.find_one({"scan_id": scan_id})
        if not scan:
            raise ResourceNotFoundException(f"Scan {scan_id} not found")
        
        if not can_access_resource(user, str(scan.get("user_id"))):
            raise AuthorizationException(f"Not authorized to cancel scan {scan_id}")
        
        service = ScanService(db)
        result = await service.cancel(scan_id)
        
        if result.get("state") == "NOT_FOUND":
            raise ResourceNotFoundException(f"Scan {scan_id} not found")
        
        return {"scan_id": scan_id, "status": "CANCELLED"}
    except (ResourceNotFoundException, AuthorizationException) as e:
        raise e.to_http_exception()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to cancel scan: {str(e)}")

