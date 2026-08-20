from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, func
from sqlalchemy.orm import relationship
from app.database.connection import Base

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    session_id = Column(String(100), ForeignKey("sessions.id", ondelete="SET NULL"), nullable=True)
    organization_id = Column(String(50), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    
    event_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False)
    ip_address = Column(String(50), nullable=False)
    device_info = Column(String(255), nullable=True)
    timestamp = Column(DateTime, default=func.now(), nullable=False, index=True)
    
    # Trust score impact logging
    previous_trust_score = Column(Integer, nullable=False)
    score_change = Column(Integer, nullable=False)
    new_trust_score = Column(Integer, nullable=False)
    risk_level = Column(String(20), nullable=False)
    action_taken = Column(String(100), nullable=False)
    explainable_reason = Column(String(500), nullable=False)

    # Relationships
    user = relationship("User", back_populates="security_events")
    session = relationship("Session", back_populates="security_events")
    organization = relationship("Organization", back_populates="security_events")
