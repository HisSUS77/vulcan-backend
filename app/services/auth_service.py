from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException, status

from app.models.user import User
from app.core.security import verify_password, get_password_hash, create_access_token
from app.core.config import settings


class AuthService:
    async def register(self, session: AsyncSession, email: str, password: str, full_name: Optional[str]) -> User:
        existed = await session.execute(select(User).where(User.email == email))
        if existed.scalar_one_or_none():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

        user = User(email=email, hashed_password=get_password_hash(password), full_name=full_name or "", role="USER")
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user

    async def authenticate(self, session: AsyncSession, email: str, password: str) -> User:
        result = await session.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()
        if not user or not verify_password(password, user.hashed_password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
        return user

    def issue_token(self, user: User) -> dict:
        token = create_access_token(str(user.id), extra_claims={"role": user.role})
        return {"access_token": token, "token_type": "bearer", "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60}
