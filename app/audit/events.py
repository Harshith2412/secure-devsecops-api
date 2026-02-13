"""
Security event types for audit logging.
"""
from enum import Enum


class EventType(str, Enum):
    """Security event types tracked in audit logs."""
    
    # Authentication events
    REGISTER_SUCCESS = "register_success"
    REGISTER_FAILED = "register_failed"
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGOUT_SUCCESS = "logout_success"
    LOGOUT_FAILED = "logout_failed"
    
    # Token events
    REFRESH_SUCCESS = "refresh_success"
    REFRESH_FAILED = "refresh_failed"
    REFRESH_REUSE_DETECTED = "refresh_reuse_detected"
    TOKEN_REVOKED = "token_revoked"
    
    # Authorization events
    ACCESS_DENIED = "access_denied"
    ADMIN_ACTION = "admin_action"
    RBAC_VIOLATION = "rbac_violation"
    
    # Rate limiting
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    
    # General access
    ENDPOINT_ACCESSED = "endpoint_accessed"
    PROFILE_ACCESSED = "profile_accessed"