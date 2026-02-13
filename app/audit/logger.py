"""
Security audit logging.
Logs all security-relevant events to the database.
"""
import json
from typing import Optional, Dict, Any
from fastapi import Request
from sqlalchemy.orm import Session
from app.db.repo import AuditLogRepository
from app.audit.events import EventType


def log_security_event(
    db: Session,
    event_type: EventType,
    request: Request,
    user_id: Optional[int] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> None:
    """
    Log a security event to the audit log.
    
    Args:
        db: Database session
        event_type: Type of security event
        request: FastAPI request object
        user_id: Optional user ID associated with the event
        metadata: Optional additional context as a dictionary
    """
    repo = AuditLogRepository(db)
    
    # Extract request information
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    endpoint = request.url.path
    
    # Serialize metadata to JSON
    metadata_json = json.dumps(metadata) if metadata else None
    
    try:
        repo.create(
            event_type=event_type.value,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            endpoint=endpoint,
            event_metadata=metadata_json  # ← CHANGED parameter name
        )
        db.commit()
    except Exception as e:
        # Log failure should not crash the application
        print(f"Failed to write audit log: {e}")
        db.rollback()