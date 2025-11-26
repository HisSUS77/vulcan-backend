from datetime import datetime
from pydantic import BaseModel, EmailStr, Field
from app.schemas.common import APIModel


class UserCreate(APIModel):
    email: EmailStr
    password: str = Field(min_length=6)
    full_name: str | None = None


class UserRead(APIModel):
    id: int
    email: EmailStr
    full_name: str | None = None
    role: str
    is_active: bool
    is_superuser: bool
    created_at: datetime | None = None


class UserLogin(APIModel):
    email: EmailStr
    password: str


class Token(APIModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
