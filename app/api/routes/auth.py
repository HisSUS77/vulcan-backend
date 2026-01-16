from fastapi import APIRouter, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import get_current_user
from app.db.mongo import get_mongo_db
from app.schemas.auth import (
    UserCreate,
    UserLogin,
    UserRead,
    Token,
    PasswordResetRequest,
    PasswordResetConfirm,
    PasswordResetValidate,
    PasswordResetValidation,
    Message,
)
from app.schemas.user import UserPublic
from app.services.auth_service import AuthService
from app.core.exceptions import ConflictException, AuthenticationException


router = APIRouter(prefix="/auth", tags=["auth"])
auth_service = AuthService()


@router.post("/register", response_model=UserRead, status_code=201)
async def register(payload: UserCreate, db: AsyncIOMotorDatabase = Depends(get_mongo_db)):
    """
    Register a new user account.
    
    - email: Must be unique
    - password: Minimum 6 characters (will be hashed with bcrypt)
    - full_name: Optional
    
    New users are assigned 'normal' role by default.
    """
    try:
        user = await auth_service.register(db, payload.email, payload.password, payload.full_name)
        return auth_service.to_public(user)
    except ConflictException as e:
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")


@router.post("/login", response_model=Token)
async def login(payload: UserLogin, db: AsyncIOMotorDatabase = Depends(get_mongo_db)):
    """
    Authenticate user with email and password.
    
    Returns JWT access token valid for the configured expiration time.
    """
    try:
        user = await auth_service.authenticate(db, payload.email, payload.password)
        return auth_service.issue_token(user)
    except AuthenticationException as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")


@router.post("/logout")
async def logout(user=Depends(get_current_user)):
    """
    Logout user (client should discard token).
    Note: This is a stateless operation since we use JWT tokens.
    """
    return {"message": "Logged out successfully"}


@router.get("/me", response_model=UserPublic)
async def me(user=Depends(get_current_user)):
    """
    Get current authenticated user profile.
    """
    return user


@router.post("/refresh", response_model=Token)
async def refresh(user=Depends(get_current_user)):
    """
    Refresh access token for the current user.
    Returns a new access token with updated expiration.
    """
    return auth_service.issue_token(user)


@router.get("/oauth/github")
async def oauth_github():
    """OAuth2 GitHub login (Not Implemented)."""
    raise HTTPException(status_code=501, detail="GitHub OAuth not implemented yet")


@router.get("/oauth/google")
async def oauth_google():
    """OAuth2 Google login (Not Implemented)."""
    raise HTTPException(status_code=501, detail="Google OAuth not implemented yet")


@router.post("/forgot-password", response_model=Message)
async def forgot_password(payload: PasswordResetRequest, db: AsyncIOMotorDatabase = Depends(get_mongo_db)):
    """
    Request a password reset email.
    Always returns success to avoid leaking account existence.
    """
    try:
        await auth_service.request_password_reset(db, payload.email)
        return Message(message="If the account exists, a reset email has been sent.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to request password reset: {str(e)}")


@router.post("/reset-password", response_model=Message)
async def reset_password(payload: PasswordResetConfirm, db: AsyncIOMotorDatabase = Depends(get_mongo_db)):
    """
    Reset password using a valid reset token.
    """
    try:
        await auth_service.reset_password(db, payload.token, payload.new_password)
        return Message(message="Password reset successfully.")
    except AuthenticationException as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to reset password: {str(e)}")


@router.post("/validate-reset-token", response_model=PasswordResetValidation)
async def validate_reset_token(payload: PasswordResetValidate, db: AsyncIOMotorDatabase = Depends(get_mongo_db)):
    """
    Validate a password reset token before showing the reset form.
    """
    try:
        is_valid = await auth_service.validate_reset_token(db, payload.token)
        if not is_valid:
            return PasswordResetValidation(valid=False, message="Invalid or expired reset token.")
        return PasswordResetValidation(valid=True, message="Token is valid.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to validate reset token: {str(e)}")
