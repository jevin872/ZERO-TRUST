from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, func
from sqlalchemy.orm import relationship
from app.database.connection import Base

class Session(Base):
    __tablename__ = "sessions"

    id = Column(String(100), primary_key=True, index=True) # UUID string format
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    refresh_token = Column(String(255), unique=True, nullable=True, index=True)
    ip_address = Column(String(50), nullable=False)
    user_agent = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=func.now(), nullable=False)
    expires_at = Column(DateTime, nullable=False)

    # Relationships
    user = relationship("User", back_populates="sessions")
    security_events = relationship("SecurityEvent", back_populates="session", cascade="all, delete-orphan")
