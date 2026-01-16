"""
Role-based permission system.
Provides decorators and utilities for role-based access control.
"""

from fastapi import Depends, HTTPException, status
from functools import wraps
from app.enums.role import UserRole
from app.core.exceptions import AuthorizationException


def require_role(*allowed_roles: UserRole):
    """
    Decorator to enforce role-based access control.
    
    Usage:
        @require_role(UserRole.ADMIN)
        async def admin_only_endpoint(user=Depends(get_current_user)):
            pass
        
        @require_role(UserRole.ADMIN, UserRole.PREMIUM)
        async def premium_and_admin_endpoint(user=Depends(get_current_user)):
            pass
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # The 'user' parameter should be in kwargs from FastAPI dependency injection
            user = kwargs.get('user')
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not authenticated"
                )
            
            user_role = user.get('role')
            role_values = [role.value for role in allowed_roles]
            
            if user_role not in role_values:
                raise AuthorizationException(
                    f"User role '{user_role}' is not authorized for this action. "
                    f"Required roles: {', '.join(role_values)}"
                ).to_http_exception()
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def is_admin(user: dict) -> bool:
    """Check if user is admin."""
    return user.get('role') == UserRole.ADMIN.value


def is_premium(user: dict) -> bool:
    """Check if user is premium or admin."""
    role = user.get('role')
    return role in [UserRole.PREMIUM.value, UserRole.ADMIN.value]


def is_normal(user: dict) -> bool:
    """Check if user is normal, premium, or admin."""
    return user.get('role') in [UserRole.NORMAL.value, UserRole.PREMIUM.value, UserRole.ADMIN.value]


def can_access_resource(user: dict, resource_owner_id: str) -> bool:
    """
    Check if user can access a resource.
    Admins can access all resources, users can only access their own.
    """
    if is_admin(user):
        return True
    return str(user.get('id')) == str(resource_owner_id)


def verify_resource_ownership(user: dict, owner_id: str):
    """
    Verify that user owns the resource.
    Raises AuthorizationException if not authorized.
    """
    if not can_access_resource(user, owner_id):
        raise AuthorizationException(
            f"User {user.get('id')} is not authorized to access resource owned by {owner_id}"
        ).to_http_exception()
