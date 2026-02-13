"""
Rate limiting implementation using in-memory storage.
Production systems should use Redis for distributed rate limiting.
"""
from datetime import datetime, timedelta
from typing import Dict, Tuple
from fastapi import Request, HTTPException, status
from collections import defaultdict
import threading

# In-memory storage: {(ip, endpoint): [(timestamp, count)]}
# Production: Use Redis with sliding window
_rate_limit_store: Dict[Tuple[str, str], list] = defaultdict(list)
_lock = threading.Lock()


def check_rate_limit(
    request: Request,
    max_requests: int,
    window_seconds: int = 60
) -> None:
    """
    Check if request exceeds rate limit.
    
    Args:
        request: FastAPI request object
        max_requests: Maximum requests allowed in window
        window_seconds: Time window in seconds
        
    Raises:
        HTTPException: 429 if rate limit exceeded
    """
    # Get client IP and endpoint
    client_ip = request.client.host
    endpoint = request.url.path
    key = (client_ip, endpoint)
    
    now = datetime.utcnow()
    window_start = now - timedelta(seconds=window_seconds)
    
    with _lock:
        # Clean old entries
        _rate_limit_store[key] = [
            ts for ts in _rate_limit_store[key]
            if ts > window_start
        ]
        
        # Check limit
        if len(_rate_limit_store[key]) >= max_requests:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Max {max_requests} requests per {window_seconds}s.",
                headers={"Retry-After": str(window_seconds)}
            )
        
        # Add current request
        _rate_limit_store[key].append(now)


async def rate_limit_login(request: Request):
    """Rate limiter for login endpoint."""
    from app.config import get_settings
    settings = get_settings()
    check_rate_limit(request, settings.rate_limit_login, 60)


async def rate_limit_register(request: Request):
    """Rate limiter for register endpoint."""
    from app.config import get_settings
    settings = get_settings()
    check_rate_limit(request, settings.rate_limit_register, 60)


async def rate_limit_refresh(request: Request):
    """Rate limiter for refresh endpoint."""
    from app.config import get_settings
    settings = get_settings()
    check_rate_limit(request, settings.rate_limit_refresh, 60)