"""
JWT-based authentication with refresh token rotation and reuse detection.
"""
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import jwt
from fastapi import HTTPException, status
from app.config import get_settings
from app.db.models import RefreshToken
from app.db.repo import RefreshTokenRepository
from sqlalchemy.orm import Session
import secrets

settings = get_settings()


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token.
    
    Args:
        data: Payload data to encode
        expires_delta: Optional custom expiration time
        
    Returns:
        Encoded JWT token
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "access"
    })
    
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
    return encoded_jwt


def create_refresh_token(user_id: int, db: Session) -> str:
    """
    Create a refresh token and store it in the database.
    Implements token rotation - old tokens are marked as used.
    
    Args:
        user_id: User ID to associate with the token
        db: Database session
        
    Returns:
        Refresh token string
    """
    # Generate cryptographically secure random token
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(days=settings.refresh_token_expire_days)
    
    # Store in database
    repo = RefreshTokenRepository(db)
    repo.create(user_id=user_id, token=token, expires_at=expires_at)
    
    return token


def verify_access_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Verify and decode a JWT access token.
    
    Args:
        token: JWT token to verify
        
    Returns:
        Decoded payload if valid, None otherwise
    """
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        
        # Verify token type
        if payload.get("type") != "access":
            return None
            
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except (jwt.InvalidTokenError, jwt.DecodeError, Exception):  # ← Fixed
        return None


def verify_refresh_token(token: str, db: Session) -> Optional[RefreshToken]:
    """
    Verify a refresh token and implement reuse detection.
    
    If a token that has already been used is presented again,
    this indicates a potential token theft. The entire token family
    is revoked for security.
    
    Args:
        token: Refresh token to verify
        db: Database session
        
    Returns:
        RefreshToken object if valid, None otherwise
        
    Raises:
        HTTPException: 401 if token reuse is detected
    """
    repo = RefreshTokenRepository(db)
    refresh_token = repo.get_by_token(token)
    
    if not refresh_token:
        return None
    
    # CRITICAL: Detect token reuse (security breach)
    if refresh_token.is_used:
        # Token has been used before - this is a replay attack
        # Revoke all tokens for this user
        repo.revoke_all_for_user(refresh_token.user_id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token reuse detected. All sessions revoked for security.",
        )
    
    # Check if token is expired
    if refresh_token.expires_at < datetime.utcnow():
        return None
    
    # Check if token is revoked
    if refresh_token.is_revoked:
        return None
    
    return refresh_token


def rotate_refresh_token(old_token: str, db: Session) -> tuple[str, str]:
    """
    Rotate a refresh token: mark old as used, issue new tokens.
    
    Args:
        old_token: Current refresh token
        db: Database session
        
    Returns:
        Tuple of (new_access_token, new_refresh_token)
        
    Raises:
        HTTPException: 401 if token is invalid or reuse is detected
    """
    # Verify the old token
    refresh_token_obj = verify_refresh_token(old_token, db)
    if not refresh_token_obj:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )
    
    user_id = refresh_token_obj.user_id
    
    # Mark old token as used (part of rotation chain)
    repo = RefreshTokenRepository(db)
    repo.mark_as_used(refresh_token_obj.id)
    
    # Create new tokens
    access_token = create_access_token(data={"sub": user_id})
    new_refresh_token = create_refresh_token(user_id, db)
    
    return access_token, new_refresh_token


def revoke_refresh_token(token: str, db: Session) -> bool:
    """
    Revoke a refresh token (for logout).
    
    Args:
        token: Refresh token to revoke
        db: Database session
        
    Returns:
        True if revoked successfully, False otherwise
    """
    repo = RefreshTokenRepository(db)
    refresh_token = repo.get_by_token(token)
    
    if refresh_token:
        repo.revoke(refresh_token.id)
        return True
    
    return False