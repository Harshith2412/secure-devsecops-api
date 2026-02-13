"""
Unit tests for security components.
Tests hashing, JWT, RBAC, rate limiting, and validation.
"""
import pytest
from datetime import datetime, timedelta
import jwt
from app.security.hashing import hash_password, verify_password
from app.security.auth import create_access_token, verify_access_token
from app.security.validation import validate_password_strength, normalize_email
from app.security.rbac import Role
from app.config import get_settings

settings = get_settings()


class TestPasswordHashing:
    """Test password hashing with Argon2."""
    
    def test_hash_password(self):
        """Test password hashing."""
        password = "SecurePassword123!"
        hashed = hash_password(password)
        
        assert hashed != password
        assert hashed.startswith("$argon2")
    
    def test_verify_password_correct(self):
        """Test password verification with correct password."""
        password = "SecurePassword123!"
        hashed = hash_password(password)
        
        assert verify_password(password, hashed) is True
    
    def test_verify_password_incorrect(self):
        """Test password verification with incorrect password."""
        password = "SecurePassword123!"
        hashed = hash_password(password)
        
        assert verify_password("WrongPassword123!", hashed) is False
    
    def test_different_hashes(self):
        """Test that same password produces different hashes (salt)."""
        password = "SecurePassword123!"
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        
        assert hash1 != hash2
        assert verify_password(password, hash1)
        assert verify_password(password, hash2)


class TestJWT:
    """Test JWT token creation and verification."""
    
    def test_create_access_token(self):
        """Test JWT access token creation."""
        data = {"sub": 1}
        token = create_access_token(data)
        
        assert isinstance(token, str)
        assert len(token) > 0
    
    def test_verify_valid_token(self):
        """Test verification of valid token."""
        data = {"sub": 1}
        token = create_access_token(data)
        payload = verify_access_token(token)
        
        assert payload is not None
        assert payload["sub"] == 1
        assert payload["type"] == "access"
    
    def test_verify_expired_token(self):
        """Test verification of expired token."""
        data = {"sub": 1}
        token = create_access_token(data, expires_delta=timedelta(seconds=-1))
        payload = verify_access_token(token)
        
        assert payload is None
    
    def test_verify_tampered_token(self):
        """Test verification of tampered token."""
        data = {"sub": 1}
        token = create_access_token(data)
        
        # Tamper with token
        tampered_token = token[:-5] + "abcde"
        payload = verify_access_token(tampered_token)
        
        assert payload is None
    
    def test_token_contains_required_fields(self):
        """Test that token contains required fields."""
        data = {"sub": 1}
        token = create_access_token(data)
        payload = verify_access_token(token)
        
        assert "sub" in payload
        assert "exp" in payload
        assert "iat" in payload
        assert "type" in payload


class TestRBAC:
    """Test Role-Based Access Control."""
    
    def test_role_enum(self):
        """Test Role enum values."""
        assert Role.USER.value == "user"
        assert Role.ADMIN.value == "admin"
    
    def test_role_values(self):
        """Test all role values are strings."""
        for role in Role:
            assert isinstance(role.value, str)


class TestValidation:
    """Test input validation functions."""
    
    def test_password_strength_valid(self):
        """Test valid password passes validation."""
        is_valid, error = validate_password_strength("SecurePass123!")
        assert is_valid is True
        assert error is None
    
    def test_password_too_short(self):
        """Test password that's too short."""
        is_valid, error = validate_password_strength("Short1!")
        assert is_valid is False
        assert "at least" in error
    
    def test_password_no_uppercase(self):
        """Test password without uppercase letter."""
        is_valid, error = validate_password_strength("securepass123!")
        assert is_valid is False
        assert "uppercase" in error.lower()
    
    def test_password_no_lowercase(self):
        """Test password without lowercase letter."""
        is_valid, error = validate_password_strength("SECUREPASS123!")
        assert is_valid is False
        assert "lowercase" in error.lower()
    
    def test_password_no_digit(self):
        """Test password without digit."""
        is_valid, error = validate_password_strength("SecurePassword!")
        assert is_valid is False
        assert "digit" in error.lower()
    
    def test_password_no_special(self):
        """Test password without special character."""
        is_valid, error = validate_password_strength("SecurePassword123")
        assert is_valid is False
        assert "special" in error.lower()
    
    def test_normalize_email(self):
        """Test email normalization."""
        assert normalize_email("Test@Example.COM") == "test@example.com"
        assert normalize_email("  test@example.com  ") == "test@example.com"


class TestRateLimit:
    """Test rate limiting functionality."""
    
    def test_rate_limit_config(self):
        """Test rate limit configuration."""
        assert settings.rate_limit_login > 0
        assert settings.rate_limit_register > 0
        assert settings.rate_limit_refresh > 0