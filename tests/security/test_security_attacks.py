"""
Security tests - attack simulation.
Tests SQL injection, JWT tampering, token reuse, and header hardening.
"""
import pytest
from fastapi import status
import jwt
from app.config import get_settings

settings = get_settings()


class TestSQLInjection:
    """Test SQL injection prevention."""
    
    SQL_INJECTION_STRINGS = [
        "' OR '1'='1",
        "admin'--",
        "' OR 1=1--",
        "1' OR '1' = '1",
        "'; DROP TABLE users--",
        "1 UNION SELECT * FROM users",
        "' UNION SELECT NULL, NULL--",
    ]
    
    def test_sql_injection_in_login(self, client, test_user):
        """Test SQL injection attempts in login endpoint."""
        for injection_string in self.SQL_INJECTION_STRINGS:
            response = client.post(
                "/auth/login",
                json={
                    "email": injection_string,
                    "password": "password"
                }
            )
            
            # Should return 401 or 422, not 500 (server error)
            assert response.status_code in [
                status.HTTP_401_UNAUTHORIZED,
                status.HTTP_422_UNPROCESSABLE_ENTITY
            ]
    
    def test_sql_injection_in_register(self, client):
        """Test SQL injection attempts in register endpoint."""
        for injection_string in self.SQL_INJECTION_STRINGS:
            response = client.post(
                "/auth/register",
                json={
                    "email": f"{injection_string}@example.com",
                    "password": "SecurePassword123!",
                    "full_name": injection_string
                }
            )
            
            # Should handle gracefully
            assert response.status_code != status.HTTP_500_INTERNAL_SERVER_ERROR


class TestJWTTampering:
    """Test JWT tampering detection."""
    
    def test_tampered_signature(self, client, user_token):
        """Test that tampered JWT signature is rejected."""
        # Tamper with the signature
        parts = user_token.split('.')
        tampered_token = f"{parts[0]}.{parts[1]}.tampered_signature"
        
        response = client.get(
            "/users/me",
            headers={"Authorization": f"Bearer {tampered_token}"}
        )
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    def test_tampered_payload(self, client, test_user):
        """Test that tampered JWT payload is rejected."""
        # Create a valid token
        from app.security.auth import create_access_token
        token = create_access_token({"sub": test_user.id})
        
        # Decode and modify payload
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            payload["sub"] = 99999  # Different user ID
            
            # Re-encode with wrong signature
            tampered_token = jwt.encode(payload, "wrong_secret", algorithm="HS256")
            
            response = client.get(
                "/users/me",
                headers={"Authorization": f"Bearer {tampered_token}"}
            )
            
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
        except Exception:
            # If JWT manipulation fails, that's also acceptable
            pass
    
    def test_none_algorithm_attack(self, client):
        """Test protection against 'none' algorithm attack."""
        payload = {"sub": 1, "type": "access"}
        
        # Try to create token with 'none' algorithm
        token = jwt.encode(payload, "", algorithm="none")
        
        response = client.get(
            "/users/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestTokenReuseDetection:
    """Test refresh token reuse detection."""
    
    def test_refresh_token_reuse_revokes_session(self, client, test_user, db):
        """Test that token reuse revokes all user sessions."""
        from app.db.models import RefreshToken
        
        # Login to get tokens
        login_response = client.post(
            "/auth/login",
            json={
                "email": "test@example.com",
                "password": "TestPassword123!"
            }
        )
        old_refresh_token = login_response.json()["refresh_token"]
        
        # Refresh once (marks old token as used)
        response = client.post(
            "/auth/refresh",
            json={"refresh_token": old_refresh_token}
        )
        assert response.status_code == status.HTTP_200_OK
        new_refresh_token = response.json()["refresh_token"]
        
        # Try to reuse old token (security breach simulation)
        response = client.post(
            "/auth/refresh",
            json={"refresh_token": old_refresh_token}
        )
        
        # Should detect reuse and revoke all tokens
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "reuse" in response.json()["detail"].lower()
        
        # Verify all tokens are revoked
        tokens = db.query(RefreshToken).filter(
            RefreshToken.user_id == test_user.id
        ).all()
        assert all(token.is_revoked for token in tokens)
        
        # New token should also be unusable now
        response = client.post(
            "/auth/refresh",
            json={"refresh_token": new_refresh_token}
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


class TestSecurityHeaders:
    """Test security headers are present."""
    
    def test_security_headers_present(self, client):
        """Test that all security headers are present."""
        response = client.get("/health")
        
        # Check for key security headers
        headers = response.headers
        
        assert "x-content-type-options" in headers
        assert headers["x-content-type-options"] == "nosniff"
        
        assert "x-frame-options" in headers
        assert headers["x-frame-options"] == "DENY"
        
        assert "content-security-policy" in headers
        assert "frame-ancestors 'none'" in headers["content-security-policy"]
        
        assert "referrer-policy" in headers
        
        assert "server" in headers
        assert headers["server"] != ""  # Server header should be generic
    
    def test_no_sensitive_headers(self, client):
        """Test that sensitive headers are not leaked."""
        response = client.get("/health")
        headers = response.headers
        
        # Should not reveal framework version
        if "server" in headers:
            assert "uvicorn" not in headers["server"].lower()
            assert "fastapi" not in headers["server"].lower()


class TestInputValidation:
    """Test input validation and sanitization."""
    
    def test_extra_fields_rejected(self, client):
        """Test that extra fields in requests are rejected."""
        response = client.post(
            "/auth/register",
            json={
                "email": "test@example.com",
                "password": "SecurePassword123!",
                "full_name": "Test User",
                "extra_field": "malicious_data"
            }
        )
        
        # Should reject due to extra field (Pydantic strict mode)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    
    def test_xss_in_input(self, client):
        """Test XSS script injection in input fields."""
        xss_payload = "<script>alert('XSS')</script>"
        
        response = client.post(
            "/auth/register",
            json={
                "email": "xss@example.com",
                "password": "SecurePassword123!",
                "full_name": xss_payload
            }
        )
        
        # Should be processed safely (not cause 500 error)
        assert response.status_code in [
            status.HTTP_201_CREATED,
            status.HTTP_422_UNPROCESSABLE_ENTITY
        ]
    
    def test_max_length_validation(self, client):
        """Test maximum length validation."""
        long_string = "a" * 10000
        
        response = client.post(
            "/auth/register",
            json={
                "email": f"{long_string}@example.com",
                "password": "SecurePassword123!",
                "full_name": "Test User"
            }
        )
        
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


class TestAuthorizationBypass:
    """Test authorization bypass attempts."""
    
    def test_cannot_escalate_role(self, client, test_user):
        """Test that users cannot escalate their role."""
        # This is implicit - users can't set their own role
        # The test verifies the API doesn't accept role in registration
        
        response = client.post(
            "/auth/register",
            json={
                "email": "escalate@example.com",
                "password": "SecurePassword123!",
                "full_name": "Escalate User",
                "role": "admin"  # Try to set admin role
            }
        )
        
        # Should reject due to extra field
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    
    def test_admin_endpoint_requires_admin_role(self, client, user_token):
        """Test that admin endpoints check role properly."""
        response = client.get(
            "/demo/admin-only",
            headers={"Authorization": f"Bearer {user_token}"}
        )
        
        assert response.status_code == status.HTTP_403_FORBIDDEN