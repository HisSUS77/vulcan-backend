from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
import uuid

from motor.motor_asyncio import AsyncIOMotorDatabase


class PatchRepository:
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db

    @property
    def patches(self):
        return self.db.patches

    @property
    def apply_requests(self):
        return self.db.patch_apply_requests

    @property
    def rate_limits(self):
        return self.db.patch_rate_limits

    async def create_patch(self, doc: Dict[str, Any]) -> str:
        patch_id = doc.get("patch_id") or str(uuid.uuid4())
        doc["patch_id"] = patch_id
        doc["created_at"] = doc.get("created_at") or datetime.utcnow()
        doc["updated_at"] = doc.get("updated_at") or datetime.utcnow()
        await self.patches.insert_one(doc)
        return patch_id

    async def get_patch(self, patch_id: str) -> Optional[Dict[str, Any]]:
        return await self.patches.find_one({"patch_id": patch_id})

    async def update_patch(self, patch_id: str, updates: Dict[str, Any]) -> bool:
        updates["updated_at"] = datetime.utcnow()
        result = await self.patches.update_one({"patch_id": patch_id}, {"$set": updates})
        return result.modified_count > 0

    async def list_by_vulnerability_ids(self, vuln_ids: List[str]) -> List[Dict[str, Any]]:
        if not vuln_ids:
            return []
        cursor = self.patches.find({"vulnerability_id": {"$in": vuln_ids}})
        return [doc async for doc in cursor]

    async def create_pending_apply(self, patch_id: str, user_id: str, repo_id: Optional[str]) -> str:
        pending_id = str(uuid.uuid4())
        await self.apply_requests.insert_one({
            "pending_apply_id": pending_id,
            "patch_id": patch_id,
            "user_id": user_id,
            "repo_id": repo_id,
            "status": "applied_pending",
            "created_at": datetime.utcnow(),
        })
        return pending_id

    async def increment_rate_limit(self, user_id: str, limit: int, window_seconds: int) -> Dict[str, Any]:
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=window_seconds)
        record = await self.rate_limits.find_one({"user_id": user_id})
        if not record or record.get("window_start") < window_start:
            record = {"user_id": user_id, "window_start": now, "count": 1}
            await self.rate_limits.update_one(
                {"user_id": user_id},
                {"$set": record},
                upsert=True
            )
            return record

        count = record.get("count", 0) + 1
        record["count"] = count
        await self.rate_limits.update_one(
            {"user_id": user_id},
            {"$set": {"count": count, "window_start": record.get("window_start", now)}}
        )
        return record
