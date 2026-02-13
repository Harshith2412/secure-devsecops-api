"""
User management routes.
Protected endpoints requiring authentication.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.db.base import get_db
from app.db.models import User
from app.dependencies import get_current_active_user
from app.security.validation import UserResponse
from app.audit.logger import log_security_event
from app.audit.events import EventType

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """
    Get current user profile.
    
    - Requires valid access token
    - Returns user information
    """
    log_security_event(
        db=db,
        event_type=EventType.PROFILE_ACCESSED,
        request=request,
        user_id=current_user.id,
        metadata={"endpoint": "/me"}
    )
    
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        full_name=current_user.full_name,
        role=current_user.role,
        is_active=current_user.is_active,
        created_at=current_user.created_at.isoformat()
    )