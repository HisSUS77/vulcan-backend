from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user
from app.schemas.auth import UserCreate, UserLogin, UserRead, Token
from app.schemas.user import UserPublic
from app.services.auth_service import AuthService


router = APIRouter(prefix="/auth", tags=["auth"])
auth_service = AuthService()


@router.post("/register", response_model=UserRead, status_code=201)
async def register(payload: UserCreate, session: AsyncSession = Depends(get_db)):
    user = await auth_service.register(session, payload.email, payload.password, payload.full_name)
    return user


@router.post("/login", response_model=Token)
async def login(payload: UserLogin, session: AsyncSession = Depends(get_db)):
    user = await auth_service.authenticate(session, payload.email, payload.password)
    return auth_service.issue_token(user)


@router.post("/logout")
async def logout():
    return {"ok": True}


@router.get("/me", response_model=UserPublic)
async def me(user=Depends(get_current_user)):
    return user


@router.post("/refresh", response_model=Token)
async def refresh(user=Depends(get_current_user)):
    return auth_service.issue_token(user)


@router.get("/oauth/github")
async def oauth_github():
    raise HTTPException(status_code=501, detail="Not Implemented")


@router.get("/oauth/google")
async def oauth_google():
    raise HTTPException(status_code=501, detail="Not Implemented")
