import pytest

from app.patch_module.guards import enforce_slice_length, reject_secrets, enforce_rate_limit
from app.core.exceptions import ValidationException, RateLimitException
from tests.patch_module._fake_db import FakeDB


def test_enforce_slice_length():
    too_long = "\n".join(["line"] * 201)
    with pytest.raises(ValidationException):
        enforce_slice_length(too_long)


def test_reject_secrets():
    secret = "AKIA" + "A" * 16
    with pytest.raises(ValidationException):
        reject_secrets(secret)


@pytest.mark.asyncio
async def test_enforce_rate_limit():
    db = FakeDB()
    for _ in range(10):
        await enforce_rate_limit(db, "user-1")
    with pytest.raises(RateLimitException):
        await enforce_rate_limit(db, "user-1")
