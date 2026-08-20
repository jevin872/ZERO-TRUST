from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class AuditLogResponse(BaseModel):
    id: int
    actor_username: str
    target_username: Optional[str] = None
    action: str
    event_type: Optional[str] = None
    previous_state: Optional[str] = None
    new_state: Optional[str] = None
    ip_address: Optional[str] = None
    reason: Optional[str] = None
    timestamp: datetime

    class Config:
        from_attributes = True
