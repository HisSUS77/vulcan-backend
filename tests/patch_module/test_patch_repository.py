import pytest

from app.patch_module.patch_repository import PatchRepository
from tests.patch_module._fake_db import FakeDB


@pytest.mark.asyncio
async def test_patch_repository_crud():
    db = FakeDB()
    repo = PatchRepository(db)

    patch_id = await repo.create_patch({
        "vulnerability_id": "v-1",
        "user_id": "u-1",
        "file_path": "app.py",
        "language": "python",
        "unified_diff": "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-a\n+b",
        "explanation": "test",
        "confidence": 0.8,
        "validations": [],
        "status": "generated",
    })

    assert patch_id
    patch = await repo.get_patch(patch_id)
    assert patch["patch_id"] == patch_id

    updated = await repo.update_patch(patch_id, {"status": "validated"})
    assert updated is True
    patch = await repo.get_patch(patch_id)
    assert patch["status"] == "validated"

    results = await repo.list_by_vulnerability_ids(["v-1"])
    assert len(results) == 1


@pytest.mark.asyncio
async def test_patch_repository_pending_apply_and_rate_limit():
    db = FakeDB()
    repo = PatchRepository(db)

    patch_id = await repo.create_patch({
        "vulnerability_id": "v-2",
        "user_id": "u-2",
        "file_path": "app.py",
        "language": "python",
        "unified_diff": "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-a\n+b",
        "explanation": "test",
        "confidence": 0.8,
        "validations": [],
        "status": "generated",
    })

    pending_id = await repo.create_pending_apply(patch_id, "u-2", "repo-1")
    assert pending_id

    record = await repo.increment_rate_limit("u-2", limit=10, window_seconds=3600)
    assert record["count"] == 1
