from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class SessionResponse(BaseModel):
    id: str
    user_id: int
    ip_address: str
    user_agent: Optional[str] = None
    is_active: bool
    created_at: datetime
    expires_at: datetime

    class Config:
        from_attributes = True
