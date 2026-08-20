from sqlalchemy import Column, Integer, String, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from app.database.connection import Base

class ScoringRule(Base):
    __tablename__ = "scoring_rules"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(String(50), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    
    event_type = Column(String(50), nullable=False, index=True)
    score_impact = Column(Integer, nullable=False) # e.g. -15 or +5
    severity = Column(String(20), default="LOW", nullable=False) # LOW, MEDIUM, HIGH, CRITICAL
    is_enabled = Column(Boolean, default=True, nullable=False)
    
    # Repeated-event rules
    repeated_threshold = Column(Integer, default=1, nullable=False)
    time_window = Column(Integer, default=300, nullable=False) # in seconds
    
    # Recovery config
    recovery_delay = Column(Integer, default=3600, nullable=False) # in seconds
    recovery_rate = Column(Integer, default=2, nullable=False) # points recovered per interval

    # Relationships
    organization = relationship("Organization", back_populates="scoring_rules")
