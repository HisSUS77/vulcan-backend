from app.schemas.common import APIModel
from pydantic import EmailStr
from app.enums.role import UserRole


class UserPublic(APIModel):
    id: str
    email: EmailStr
    full_name: str | None = None
    role: UserRole
    is_active: bool
    is_superuser: bool = False
