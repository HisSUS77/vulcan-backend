from typing import AsyncGenerator

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from bson import ObjectId

from app.core.config import settings


def build_mongo_uri() -> str:
    if settings.MONGO_URI:
        return settings.MONGO_URI
    auth = ""
    if settings.MONGO_USER and settings.MONGO_PASSWORD:
        auth = f"{settings.MONGO_USER}:{settings.MONGO_PASSWORD}@"
    if auth:
        return (
            f"mongodb://{auth}{settings.MONGO_HOST}:{settings.MONGO_PORT}/"
            f"{settings.MONGO_DB_NAME}?authSource=admin"
        )
    return f"mongodb://{settings.MONGO_HOST}:{settings.MONGO_PORT}/{settings.MONGO_DB_NAME}"


_mongo_client = AsyncIOMotorClient(build_mongo_uri())


def get_mongo_database() -> AsyncIOMotorDatabase:
    return _mongo_client[settings.MONGO_DB_NAME]


async def get_mongo_db() -> AsyncGenerator[AsyncIOMotorDatabase, None]:
    yield get_mongo_database()


def to_object_id(value: str) -> ObjectId | None:
    if ObjectId.is_valid(value):
        return ObjectId(value)
    return None
