from fastapi import APIRouter, Depends
from motor.motor_asyncio import AsyncIOMotorDatabase
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.deps import get_current_user, get_db
from app.db.mongo import get_mongo_db, to_object_id
from app.enums.role import UserRole
from app.models.repository import Repository
from app.services.notification_service import NotificationService
from app.patch_module.patch_repository import PatchRepository


router = APIRouter(prefix="/dashboard", tags=["dashboard"])
notif_service = NotificationService()


@router.get("/summary")
async def summary(
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
    session: AsyncSession = Depends(get_db),
):
    query = {}
    if user.get("role") != UserRole.ADMIN.value:
        object_id = to_object_id(user.get("id", ""))
        if object_id:
            query["user_id"] = object_id
        else:
            query["user_id"] = None

    scans = await db.scans.find(query).to_list(length=500)
    total_scans = len(scans)
    total_vulns = 0
    severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for scan in scans:
        summary = scan.get("summary") or {}
        total_vulns += summary.get("vulnerabilities_found", 0)
        by_sev = summary.get("by_severity", {})
        severity["CRITICAL"] += by_sev.get("critical", 0)
        severity["HIGH"] += by_sev.get("high", 0)
        severity["MEDIUM"] += by_sev.get("medium", 0)
        severity["LOW"] += by_sev.get("low", 0)

    repos = await session.execute(select(Repository))
    repo_count = len(list(repos.scalars().all()))

    patch_query = {}
    if user.get("role") != UserRole.ADMIN.value:
        patch_query["user_id"] = user.get("id")
    patch_repo = PatchRepository(db)
    patch_cursor = patch_repo.patches.find(patch_query)
    patches = await patch_cursor.to_list(length=1000)
    total_patches = len(patches)
    success_statuses = {"validated", "approved", "applied_pending", "applied"}
    applied_statuses = {"applied_pending", "applied"}
    successful = sum(1 for p in patches if p.get("status") in success_statuses)
    applied = sum(1 for p in patches if p.get("status") in applied_statuses)
    confidences = [p.get("confidence") for p in patches if isinstance(p.get("confidence"), (int, float))]
    avg_confidence = round(sum(confidences) / len(confidences), 2) if confidences else 0.0
    patch_success_rate = round(successful / total_patches, 2) if total_patches else 0.0

    # Risk score 0–100: weighted sum of vulns by severity, capped at 100
    # Critical=10pts, High=5pts, Medium=2pts, Low=0.5pts — saturates at 100
    raw_risk = (
        severity["CRITICAL"] * 10 +
        severity["HIGH"]     * 5  +
        severity["MEDIUM"]   * 2  +
        severity["LOW"]      * 0.5
    )
    risk_score = min(100, round(raw_risk))
    risk_label = (
        "Critical" if risk_score >= 75 else
        "High"     if risk_score >= 50 else
        "Medium"   if risk_score >= 25 else
        "Low"      if risk_score >  0  else
        "Clean"
    )

    return {
        "totals": {
            "repos": repo_count,
            "scans": total_scans,
            "vulnerabilities": total_vulns,
            "patches_total": total_patches,
            "patches_applied": applied,
        },
        "severity": severity,
        "risk": {"score": risk_score, "label": risk_label},
        "ai": {"patch_success_rate": patch_success_rate, "avg_confidence": avg_confidence},
        "trend": [],
    }


@router.get("/recent-scans")
async def recent_scans(
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
    session: AsyncSession = Depends(get_db),
):
    query = {}
    if user.get("role") != UserRole.ADMIN.value:
        object_id = to_object_id(user.get("id", ""))
        if object_id:
            query["user_id"] = object_id
        else:
            query["user_id"] = None

    cursor = db.scans.find(query).sort("created_at", -1).limit(5)
    scans = await cursor.to_list(length=5)

    repo_ids = [scan.get("repo_id") for scan in scans if scan.get("repo_id")]
    repo_map = {}
    if repo_ids:
        result = await session.execute(select(Repository).where(Repository.id.in_(repo_ids)))
        repo_map = {repo.id: repo.name for repo in result.scalars().all()}

    items = []
    for scan in scans:
        summary = scan.get("summary") or {}
        repo_id = scan.get("repo_id")
        items.append(
            {
                "scan_id": scan.get("scan_id"),
                "repo_id": repo_id,
                "repository_name": repo_map.get(repo_id) if repo_id else "Direct Code",
                "status": scan.get("state"),
                "created_at": summary.get("created_at") or scan.get("created_at"),
                "vulnerabilities_found": summary.get("vulnerabilities_found", 0),
            }
        )
    return items


@router.get("/patch-stats")
async def patch_stats(
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    """
    Live patch success rate and breakdown by status.
    Used by the dashboard AI Patch Success Rate card.
    """
    patch_query = {}
    if user.get("role") != UserRole.ADMIN.value:
        patch_query["user_id"] = user.get("id")

    patch_repo = PatchRepository(db)
    patches = await patch_repo.patches.find(patch_query).to_list(length=2000)

    total = len(patches)

    # Count each status bucket
    counts = {"applied": 0, "applied_pending": 0, "approved": 0, "validated": 0,
               "generated": 0, "failed": 0, "other": 0}
    confidences = []
    for p in patches:
        s = (p.get("status") or "other").lower()
        if s in counts:
            counts[s] += 1
        else:
            counts["other"] += 1
        c = p.get("confidence")
        if isinstance(c, (int, float)):
            confidences.append(c)

    # Success = validated + approved + applied_pending + applied
    successful = counts["validated"] + counts["approved"] + counts["applied_pending"] + counts["applied"]
    actually_applied = counts["applied"] + counts["applied_pending"]
    success_rate = round(successful / total, 4) if total else 0.0
    avg_confidence = round(sum(confidences) / len(confidences), 4) if confidences else 0.0

    return {
        "total_patches": total,
        "successful": successful,
        "applied": actually_applied,
        "success_rate": success_rate,
        "avg_confidence": avg_confidence,
        "breakdown": {
            "applied": counts["applied"],
            "applied_pending": counts["applied_pending"],
            "approved": counts["approved"],
            "validated": counts["validated"],
            "generated": counts["generated"],
            "failed": counts["failed"],
            "other": counts["other"],
        },
    }


@router.get("/notifications")
async def notifications(
    page: int = 1,
    size: int = 10,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    return await notif_service.list(db, user, page, size)
