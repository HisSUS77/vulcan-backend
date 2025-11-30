from dotenv import load_dotenv
load_dotenv()  # Load .env file before importing anything else

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api.api_v1 import api_router
from app.db.init_db import init_models, seed_admin
from app.db.session import SessionLocal


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
    async with SessionLocal() as session:
        await seed_admin(session)


app.include_router(api_router, prefix=settings.API_V1_STR)
