"""
Authentication routes: register, login, refresh, logout.
Implements secure authentication flow with audit logging.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.db.base import get_db
from app.db.repo import UserRepository
from app.security.validation import (
    RegisterRequest,
    LoginRequest,
    RefreshRequest,
    TokenResponse,
    MessageResponse,
    normalize_email
)
from app.security.hashing import hash_password, verify_password
from app.security.auth import (
    create_access_token,
    create_refresh_token,
    rotate_refresh_token,
    revoke_refresh_token
)
from app.security.rate_limit import rate_limit_login, rate_limit_register, rate_limit_refresh
from app.audit.logger import log_security_event
from app.audit.events import EventType
from app.config import get_settings

router = APIRouter(prefix="/auth", tags=["authentication"])
settings = get_settings()


@router.post(
    "/register",
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit_register)]
)
async def register(
    request: Request,
    data: RegisterRequest,
    db: Session = Depends(get_db)
):
    """
    Register a new user account.
    
    - Email must be unique
    - Password must meet security policy
    - Creates user with 'user' role by default
    """
    repo = UserRepository(db)
    
    # Normalize email
    email = normalize_email(data.email)
    
    # Check if user exists
    existing_user = repo.get_by_email(email)
    if existing_user:
        log_security_event(
            db=db,
            event_type=EventType.REGISTER_FAILED,
            request=request,
            user_id=None,
            metadata={"email": email, "reason": "duplicate"}
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Hash password
    hashed_password = hash_password(data.password)
    
    # Create user
    user = repo.create(
        email=email,
        hashed_password=hashed_password,
        full_name=data.full_name,
        role="user"
    )
    
    log_security_event(
        db=db,
        event_type=EventType.REGISTER_SUCCESS,
        request=request,
        user_id=user.id,
        metadata={"email": email}
    )
    
    return MessageResponse(
        message="User registered successfully",
        detail=f"Welcome, {user.full_name}!"
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    dependencies=[Depends(rate_limit_login)]
)
async def login(
    request: Request,
    data: LoginRequest,
    db: Session = Depends(get_db)
):
    """
    Authenticate user and return access + refresh tokens.
    
    - Returns JWT access token (15 min)
    - Returns refresh token (7 days)
    - Rate limited to prevent brute force
    """
    repo = UserRepository(db)
    
    # Normalize email
    email = normalize_email(data.email)
    
    # Get user
    user = repo.get_by_email(email)
    if not user or not verify_password(data.password, user.hashed_password):
        log_security_event(
            db=db,
            event_type=EventType.LOGIN_FAILED,
            request=request,
            user_id=None,
            metadata={"email": email, "reason": "invalid_credentials"}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    
    if not user.is_active:
        log_security_event(
            db=db,
            event_type=EventType.LOGIN_FAILED,
            request=request,
            user_id=user.id,
            metadata={"email": email, "reason": "inactive_account"}
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive"
        )
    
    # Create tokens
    access_token = create_access_token(data={"sub": user.id})
    refresh_token = create_refresh_token(user.id, db)
    
    log_security_event(
        db=db,
        event_type=EventType.LOGIN_SUCCESS,
        request=request,
        user_id=user.id,
        metadata={"email": email}
    )
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.access_token_expire_minutes * 60
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    dependencies=[Depends(rate_limit_refresh)]
)
async def refresh(
    request: Request,
    data: RefreshRequest,
    db: Session = Depends(get_db)
):
    """
    Refresh access token using refresh token.
    
    - Implements token rotation (old token marked as used)
    - Detects token reuse (security breach)
    - Returns new access + refresh tokens
    """
    try:
        access_token, new_refresh_token = rotate_refresh_token(data.refresh_token, db)
        
        # Extract user_id from the new access token for logging
        from app.security.auth import verify_access_token
        payload = verify_access_token(access_token)
        user_id = payload.get("sub") if payload else None
        
        log_security_event(
            db=db,
            event_type=EventType.REFRESH_SUCCESS,
            request=request,
            user_id=user_id,
            metadata={"token_rotated": True}
        )
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=new_refresh_token,
            expires_in=settings.access_token_expire_minutes * 60
        )
    except HTTPException as e:
        # Token reuse detected or invalid token
        log_security_event(
            db=db,
            event_type=EventType.REFRESH_REUSE_DETECTED if "reuse" in e.detail.lower() else EventType.REFRESH_FAILED,
            request=request,
            user_id=None,
            metadata={"reason": e.detail}
        )
        raise


@router.post(
    "/logout",
    response_model=MessageResponse
)
async def logout(
    request: Request,
    data: RefreshRequest,
    db: Session = Depends(get_db)
):
    """
    Logout user by revoking refresh token.
    
    - Revokes the provided refresh token
    - Access tokens cannot be revoked (short-lived by design)
    """
    success = revoke_refresh_token(data.refresh_token, db)
    
    if not success:
        log_security_event(
            db=db,
            event_type=EventType.LOGOUT_FAILED,
            request=request,
            user_id=None,
            metadata={"reason": "invalid_token"}
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid refresh token"
        )
    
    log_security_event(
        db=db,
        event_type=EventType.LOGOUT_SUCCESS,
        request=request,
        user_id=None,
        metadata={"token_revoked": True}
    )
    
    return MessageResponse(message="Logged out successfully")