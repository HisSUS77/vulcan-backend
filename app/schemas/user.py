from app.schemas.common import APIModel
from pydantic import EmailStr


class UserPublic(APIModel):
    id: int
    email: EmailStr
    full_name: str | None = None
    role: str
    is_active: bool
    is_superuser: bool
