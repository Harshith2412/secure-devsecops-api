"""
Security headers middleware.
Implements OWASP recommended security headers.
"""
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from app.config import get_settings

settings = get_settings()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Adds security headers to all responses.
    
    Headers implemented:
    - X-Content-Type-Options: nosniff
    - X-Frame-Options: DENY
    - Content-Security-Policy
    - Referrer-Policy: strict-origin-when-cross-origin
    - X-XSS-Protection: 1; mode=block (legacy)
    - Strict-Transport-Security (HSTS)
    """
    
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = f"frame-ancestors 'none'; {settings.csp_policy}"
        
        # Control referrer information
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Legacy XSS protection
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # HSTS - Force HTTPS (only if using HTTPS)
        # Uncomment in production with HTTPS
        # response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        # Remove server identification
        response.headers["Server"] = "Secure API"
        
        return response