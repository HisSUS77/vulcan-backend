from dotenv import load_dotenv
load_dotenv()  # Load .env file before importing anything else

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api.api_v1 import api_router
from app.db.init_db import init_models
from app.db.mongo_init import ensure_indexes, seed_admin


app = FastAPI(title=settings.PROJECT_NAME)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[orig.strip() for orig in settings.BACKEND_CORS_ORIGINS.split(",")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.on_event("startup")
async def on_startup():
    await init_models()
    await ensure_indexes()
    await seed_admin()


app.include_router(api_router, prefix=settings.API_V1_STR)
