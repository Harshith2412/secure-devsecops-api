"""
SQLAlchemy ORM models.
"""
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Index
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.base import Base


class User(Base):
    """User account model."""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(100), nullable=False)
    role = Column(String(20), nullable=False, default="user")  # user, admin
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<User(id={self.id}, email={self.email}, role={self.role})>"


class RefreshToken(Base):
    """Refresh token model for token rotation."""
    __tablename__ = "refresh_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token = Column(String(255), unique=True, nullable=False, index=True)
    is_used = Column(Boolean, default=False, nullable=False)  # For rotation tracking
    is_revoked = Column(Boolean, default=False, nullable=False)  # For logout
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="refresh_tokens")
    
    # Indexes for performance
    __table_args__ = (
        Index('ix_refresh_tokens_user_active', 'user_id', 'is_revoked', 'is_used'),
    )
    
    def __repr__(self):
        return f"<RefreshToken(id={self.id}, user_id={self.user_id}, used={self.is_used})>"


class AuditLog(Base):
    """Security audit log model."""
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    event_type = Column(String(50), nullable=False, index=True)  # register, login, logout, etc.
    user_id = Column(Integer, nullable=True, index=True)  # Nullable for failed attempts
    ip_address = Column(String(45), nullable=True)  # IPv6 support
    user_agent = Column(String(500), nullable=True)
    endpoint = Column(String(255), nullable=True)
    event_metadata = Column(Text, nullable=True)  # ← CHANGED FROM 'metadata' to 'event_metadata'
    
    # Indexes for querying
    __table_args__ = (
        Index('ix_audit_logs_user_event', 'user_id', 'event_type'),
        Index('ix_audit_logs_timestamp_event', 'timestamp', 'event_type'),
    )
    
    def __repr__(self):
        return f"<AuditLog(id={self.id}, event={self.event_type}, user_id={self.user_id})>"