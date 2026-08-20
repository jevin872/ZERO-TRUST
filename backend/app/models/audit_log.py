from sqlalchemy import Column, Integer, String, DateTime, func
from app.database.connection import Base

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    actor_username = Column(String(50), nullable=False) # Admin username or SYSTEM
    target_username = Column(String(50), nullable=True) # Target username
    action = Column(String(100), nullable=False) # e.g. BLOCK_USER, TERMINATE_SESSION, UPDATE_RULE
    ip_address = Column(String(50), nullable=True)
    reason = Column(String(255), nullable=True)
    timestamp = Column(DateTime, default=func.now(), nullable=False, index=True)
