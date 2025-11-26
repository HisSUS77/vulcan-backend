from fastapi import APIRouter, Depends
from app.api.deps import get_current_user
from app.services.notification_service import NotificationService


router = APIRouter(prefix="/dashboard", tags=["dashboard"])
notif_service = NotificationService()


@router.get("/summary")
async def summary(user=Depends(get_current_user)):
    return {
        "totals": {"repos": 5, "scans": 42, "vulnerabilities": 213},
        "severity": {"CRITICAL": 7, "HIGH": 23, "MEDIUM": 91, "LOW": 92},
        "ai": {"patch_success_rate": 0.71, "avg_confidence": 0.83},
        "trend": [
            {"date": "2025-11-01", "scans": 2},
            {"date": "2025-11-02", "scans": 3},
            {"date": "2025-11-03", "scans": 4},
        ],
    }


@router.get("/recent-scans")
async def recent_scans(user=Depends(get_current_user)):
    return [
        {"scan_id": "abc123", "repo": "frontend-app", "status": "COMPLETED", "created_at": "2025-11-02T11:00:00Z"},
        {"scan_id": "def456", "repo": "api-server", "status": "RUNNING", "created_at": "2025-11-03T10:00:00Z"},
    ]


@router.get("/notifications")
async def notifications(page: int = 1, size: int = 10, user=Depends(get_current_user)):
    return notif_service.list(page, size)
