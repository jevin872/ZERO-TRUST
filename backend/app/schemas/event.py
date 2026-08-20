from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class SecurityEventCreate(BaseModel):
    event_type: str
    ip_address: str
    device_info: Optional[str] = "unknown"
    severity_override: Optional[str] = None # Optional override

class SecurityEventResponse(BaseModel):
    id: int
    user_id: int
    session_id: Optional[str] = None
    event_type: str
    severity: str
    ip_address: str
    device_info: Optional[str] = None
    timestamp: datetime
    previous_trust_score: int
    score_change: int
    new_trust_score: int
    risk_level: str
    action_taken: str
    explainable_reason: str

    class Config:
        from_attributes = True
