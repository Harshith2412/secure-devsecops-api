"""
Input validation utilities and Pydantic models.
Implements strict validation and sanitization.
"""
import re
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, field_validator, ConfigDict


class StrictBaseModel(BaseModel):
    """Base model with strict validation - no extra fields allowed."""
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)


def validate_password_strength(password: str) -> tuple[bool, Optional[str]]:
    """
    Validate password against security policy.
    
    Args:
        password: Password to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    from app.config import get_settings
    settings = get_settings()
    
    if len(password) < settings.min_password_length:
        return False, f"Password must be at least {settings.min_password_length} characters"
    
    if settings.require_uppercase and not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if settings.require_lowercase and not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if settings.require_digit and not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    
    if settings.require_special and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    return True, None


def normalize_email(email: str) -> str:
    """
    Normalize email address to prevent duplicate accounts.
    
    Args:
        email: Email address to normalize
        
    Returns:
        Normalized email address (lowercase)
    """
    return email.lower().strip()


# Request/Response Models

class RegisterRequest(StrictBaseModel):
    """User registration request."""
    email: EmailStr = Field(..., max_length=255, description="User email address")
    password: str = Field(..., min_length=12, max_length=128, description="User password")
    full_name: str = Field(..., min_length=1, max_length=100, description="User full name")
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        is_valid, error = validate_password_strength(v)
        if not is_valid:
            raise ValueError(error)
        return v


class LoginRequest(StrictBaseModel):
    """User login request."""
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., description="User password")


class RefreshRequest(StrictBaseModel):
    """Token refresh request."""
    refresh_token: str = Field(..., min_length=32, description="Refresh token")


class TokenResponse(BaseModel):
    """Token response."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class UserResponse(BaseModel):
    """User profile response."""
    id: int
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: str
    
    model_config = ConfigDict(from_attributes=True)


class MessageResponse(BaseModel):
    """Generic message response."""
    message: str
    detail: Optional[str] = None