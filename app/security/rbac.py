"""
Role-Based Access Control (RBAC) implementation.
Provides decorators and dependencies for role-based authorization.
"""
from enum import Enum
from typing import List
from fastapi import Depends, HTTPException, status
from app.dependencies import get_current_active_user
from app.db.models import User


class Role(str, Enum):
    """User roles in the system."""
    USER = "user"
    ADMIN = "admin"


def require_roles(allowed_roles: List[Role]):
    """
    Dependency factory for role-based authorization.
    
    Args:
        allowed_roles: List of roles that are allowed access
        
    Returns:
        Dependency function that checks user role
        
    Example:
        @router.get("/admin-only", dependencies=[Depends(require_roles([Role.ADMIN]))])
    """
    def role_checker(current_user: User = Depends(get_current_active_user)) -> User:
        if current_user.role not in [role.value for role in allowed_roles]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required roles: {[r.value for r in allowed_roles]}",
            )
        return current_user
    
    return role_checker


def is_admin(current_user: User = Depends(get_current_active_user)) -> User:
    """
    Dependency to require admin role.
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        User if they are an admin
        
    Raises:
        HTTPException: 403 if user is not an admin
    """
    if current_user.role != Role.ADMIN.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user