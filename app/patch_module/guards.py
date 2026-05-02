from __future__ import annotations

import re
from typing import Optional

from motor.motor_asyncio import AsyncIOMotorDatabase
from app.core.exceptions import RateLimitException, ValidationException
from app.patch_module.patch_repository import PatchRepository


MAX_SLICE_LINES = int(200)
MAX_PATCHES_PER_HOUR = int(10)


SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key
    re.compile(r"(?i)api[_-]?key\\s*[:=]\\s*[\"']?[A-Za-z0-9_-]{16,}"),
    re.compile(r"(?i)secret\\s*[:=]\\s*[\"']?[A-Za-z0-9_-]{16,}"),
    re.compile(r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----"),
]


# Raise RateLimitException if the user has exceeded the hourly patch generation limit.
async def enforce_rate_limit(db: AsyncIOMotorDatabase, user_id: str) -> None:
    repo = PatchRepository(db)
    record = await repo.increment_rate_limit(user_id, MAX_PATCHES_PER_HOUR, 3600)
    if record.get("count", 0) > MAX_PATCHES_PER_HOUR:
        raise RateLimitException("Patch generation rate limit exceeded")


# Raise ValidationException if the code slice exceeds the maximum allowed line count.
def enforce_slice_length(vulnerable_slice: str) -> None:
    lines = vulnerable_slice.splitlines()
    if len(lines) > MAX_SLICE_LINES:
        raise ValidationException("Code slice too large for patch generation")


# Raise ValidationException if the code slice contains detectable secrets or private keys.
def reject_secrets(vulnerable_slice: str) -> None:
    for pattern in SECRET_PATTERNS:
        if pattern.search(vulnerable_slice):
            raise ValidationException("Secrets detected in code slice")
