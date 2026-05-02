from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
import uuid

from motor.motor_asyncio import AsyncIOMotorDatabase


class PatchRepository:
    # Store the Motor async database handle for use by all repository methods.
    def __init__(self, db: AsyncIOMotorDatabase):
        self.db = db

    # Return the patches collection from the database.
    @property
    def patches(self):
        return self.db.patches

    # Return the patch apply requests collection from the database.
    @property
    def apply_requests(self):
        return self.db.patch_apply_requests

    # Return the patch rate limits collection from the database.
    @property
    def rate_limits(self):
        return self.db.patch_rate_limits

    # Insert a new patch document into MongoDB, assigning a UUID and timestamps if absent.
    async def create_patch(self, doc: Dict[str, Any]) -> str:
        patch_id = doc.get("patch_id") or str(uuid.uuid4())
        doc["patch_id"] = patch_id
        doc["created_at"] = doc.get("created_at") or datetime.utcnow()
        doc["updated_at"] = doc.get("updated_at") or datetime.utcnow()
        await self.patches.insert_one(doc)
        return patch_id

    # Retrieve a single patch document by its patch_id, or return None if not found.
    async def get_patch(self, patch_id: str) -> Optional[Dict[str, Any]]:
        return await self.patches.find_one({"patch_id": patch_id})

    # Apply a partial update to a patch document and return True if a document was modified.
    async def update_patch(self, patch_id: str, updates: Dict[str, Any]) -> bool:
        updates["updated_at"] = datetime.utcnow()
        result = await self.patches.update_one({"patch_id": patch_id}, {"$set": updates})
        return result.modified_count > 0

    # Fetch all patch documents whose vulnerability_id is in the given list.
    async def list_by_vulnerability_ids(self, vuln_ids: List[str]) -> List[Dict[str, Any]]:
        if not vuln_ids:
            return []
        cursor = self.patches.find({"vulnerability_id": {"$in": vuln_ids}})
        return [doc async for doc in cursor]

    # Create a pending apply request record linking a patch to a user and optional repo.
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

    # Increment the per-user request counter within the rolling time window, resetting if expired.
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
