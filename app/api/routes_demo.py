"""
Demo routes to showcase RBAC and security features.
"""
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from app.db.base import get_db
from app.db.models import User
from app.dependencies import get_current_active_user
from app.security.rbac import is_admin, Role, require_roles
from app.security.validation import MessageResponse
from app.audit.logger import log_security_event
from app.audit.events import EventType

router = APIRouter(prefix="/demo", tags=["demo"])


@router.get("/protected", response_model=MessageResponse)
async def protected_endpoint(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Protected endpoint - requires authentication.
    
    - Any authenticated user can access
    """
    log_security_event(
        db=db,
        event_type=EventType.ENDPOINT_ACCESSED,
        request=request,
        user_id=current_user.id,
        metadata={"endpoint": "/demo/protected", "role": current_user.role}
    )
    
    return MessageResponse(
        message="Access granted to protected resource",
        detail=f"Hello, {current_user.full_name}!"
    )


@router.get("/admin-only", response_model=MessageResponse)
async def admin_only_endpoint(
    request: Request,
    current_user: User = Depends(is_admin),
    db: Session = Depends(get_db)
):
    """
    Admin-only endpoint.
    
    - Requires admin role
    - Returns 403 for non-admin users
    """
    log_security_event(
        db=db,
        event_type=EventType.ADMIN_ACTION,
        request=request,
        user_id=current_user.id,
        metadata={"endpoint": "/demo/admin-only", "action": "accessed"}
    )
    
    return MessageResponse(
        message="Admin access granted",
        detail="You have administrative privileges"
    )


@router.get("/user-or-admin", response_model=MessageResponse)
async def multi_role_endpoint(
    request: Request,
    current_user: User = Depends(require_roles([Role.USER, Role.ADMIN])),
    db: Session = Depends(get_db)
):
    """
    Endpoint accessible by users or admins.
    
    - Demonstrates multi-role authorization
    """
    log_security_event(
        db=db,
        event_type=EventType.ENDPOINT_ACCESSED,
        request=request,
        user_id=current_user.id,
        metadata={"endpoint": "/demo/user-or-admin", "role": current_user.role}
    )
    
    return MessageResponse(
        message="Access granted",
        detail=f"Authenticated as {current_user.role}"
    )