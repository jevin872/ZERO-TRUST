from sqlalchemy import Column, String, DateTime, func
from sqlalchemy.orm import relationship
from app.database.connection import Base

class Organization(Base):
    __tablename__ = "organizations"

    id = Column(String(50), primary_key=True, index=True) # e.g. "DEMO_BANK", "HOSPITAL"
    name = Column(String(100), nullable=False)
    industry = Column(String(50), nullable=False) # e.g. "Finance", "Healthcare"
    created_at = Column(DateTime, default=func.now(), nullable=False)

    # Relationships
    users = relationship("User", back_populates="organization", cascade="all, delete-orphan")
    scoring_rules = relationship("ScoringRule", back_populates="organization", cascade="all, delete-orphan")
    security_events = relationship("SecurityEvent", back_populates="organization", cascade="all, delete-orphan")
