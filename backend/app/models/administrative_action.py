from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, func
from app.database.connection import Base

class AdministrativeAction(Base):
    __tablename__ = "administrative_actions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    action_type = Column(String(50), nullable=False) # e.g. BLOCK, UNBLOCK, TERMINATE_SESSION
    performed_by = Column(String(50), nullable=False) # Admin username
    ip_address = Column(String(50), nullable=True)
    reason = Column(String(255), nullable=True)
    timestamp = Column(DateTime, default=func.now(), nullable=False, index=True)
