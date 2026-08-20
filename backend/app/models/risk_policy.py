from sqlalchemy import Column, Integer, String, Boolean, ForeignKey
from app.database.connection import Base

class RiskPolicy(Base):
    __tablename__ = "risk_policies"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(String(50), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    risk_level = Column(String(20), nullable=False) # LOW, MEDIUM_LOW, MEDIUM_HIGH, HIGH, CRITICAL
    enforced_action = Column(String(50), nullable=False) # e.g. ALLOW_ACCESS, REQUIRE_MFA, etc.
    is_enabled = Column(Boolean, default=True, nullable=False)
