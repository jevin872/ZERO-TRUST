from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, func
from sqlalchemy.orm import relationship
from app.database.connection import Base

class TrustScore(Base):
    __tablename__ = "trust_scores"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False)
    current_score = Column(Integer, default=100, nullable=False)
    risk_level = Column(String(20), default="LOW", nullable=False)
    last_updated = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships
    user = relationship("User", back_populates="trust_score")

class TrustScoreHistory(Base):
    __tablename__ = "trust_score_history"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    previous_score = Column(Integer, nullable=False)
    new_score = Column(Integer, nullable=False)
    score_change = Column(Integer, nullable=False)
    event_type = Column(String(50), nullable=False)
    timestamp = Column(DateTime, default=func.now(), nullable=False, index=True)

    # Relationships
    user = relationship("User", back_populates="trust_history")
