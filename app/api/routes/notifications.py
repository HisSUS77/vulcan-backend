from fastapi import APIRouter, Depends
from app.api.deps import get_current_user
from app.services.notification_service import NotificationService


router = APIRouter(prefix="/notifications", tags=["notifications"])
service = NotificationService()


@router.get("")
async def list_notifications(page: int = 1, size: int = 10, user=Depends(get_current_user)):
    return service.list(page, size)
