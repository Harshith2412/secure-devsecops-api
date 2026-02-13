"""
Repository pattern for database operations.
Provides a clean interface for CRUD operations.
"""
from typing import Optional, List
from datetime import datetime
from sqlalchemy.orm import Session
from app.db.models import User, RefreshToken, AuditLog


class UserRepository:
    """Repository for User operations."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def create(
        self,
        email: str,
        hashed_password: str,
        full_name: str,
        role: str = "user"
    ) -> User:
        """Create a new user."""
        user = User(
            email=email,
            hashed_password=hashed_password,
            full_name=full_name,
            role=role
        )
        self.db.add(user)
        self.db.flush()
        return user
    
    def get_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID."""
        return self.db.query(User).filter(User.id == user_id).first()
    
    def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        return self.db.query(User).filter(User.email == email).first()
    
    def get_all(self) -> List[User]:
        """Get all users."""
        return self.db.query(User).all()


class RefreshTokenRepository:
    """Repository for RefreshToken operations."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def create(self, user_id: int, token: str, expires_at: datetime) -> RefreshToken:
        """Create a new refresh token."""
        refresh_token = RefreshToken(
            user_id=user_id,
            token=token,
            expires_at=expires_at
        )
        self.db.add(refresh_token)
        self.db.flush()
        return refresh_token
    
    def get_by_token(self, token: str) -> Optional[RefreshToken]:
        """Get refresh token by token string."""
        return self.db.query(RefreshToken).filter(RefreshToken.token == token).first()
    
    def mark_as_used(self, token_id: int) -> None:
        """Mark a refresh token as used (rotation)."""
        self.db.query(RefreshToken).filter(RefreshToken.id == token_id).update(
            {"is_used": True}
        )
        self.db.flush()
    
    def revoke(self, token_id: int) -> None:
        """Revoke a refresh token (logout)."""
        self.db.query(RefreshToken).filter(RefreshToken.id == token_id).update(
            {"is_revoked": True}
        )
        self.db.flush()
    
    def revoke_all_for_user(self, user_id: int) -> None:
        """Revoke all refresh tokens for a user (security breach response)."""
        self.db.query(RefreshToken).filter(RefreshToken.user_id == user_id).update(
            {"is_revoked": True}
        )
        self.db.flush()
    
    def cleanup_expired(self) -> int:
        """Delete expired tokens. Returns count of deleted tokens."""
        result = self.db.query(RefreshToken).filter(
            RefreshToken.expires_at < datetime.utcnow()
        ).delete()
        self.db.flush()
        return result


class AuditLogRepository:
    """Repository for AuditLog operations."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def create(
        self,
        event_type: str,
        user_id: Optional[int] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        endpoint: Optional[str] = None,
        event_metadata: Optional[str] = None  # ← CHANGED parameter name
    ) -> AuditLog:
        """Create a new audit log entry."""
        log = AuditLog(
            event_type=event_type,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            endpoint=endpoint,
            event_metadata=event_metadata  # ← CHANGED field name
        )
        self.db.add(log)
        self.db.flush()
        return log
    
    def get_by_user(self, user_id: int, limit: int = 100) -> List[AuditLog]:
        """Get audit logs for a specific user."""
        return self.db.query(AuditLog).filter(
            AuditLog.user_id == user_id
        ).order_by(AuditLog.timestamp.desc()).limit(limit).all()
    
    def get_by_event_type(self, event_type: str, limit: int = 100) -> List[AuditLog]:
        """Get audit logs by event type."""
        return self.db.query(AuditLog).filter(
            AuditLog.event_type == event_type
        ).order_by(AuditLog.timestamp.desc()).limit(limit).all()