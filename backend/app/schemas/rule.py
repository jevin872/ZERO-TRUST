from pydantic import BaseModel
from typing import Optional

class ScoringRuleBase(BaseModel):
    event_type: str
    score_impact: int
    severity: str
    is_enabled: bool = True
    repeated_threshold: int = 1
    time_window: int = 300
    recovery_delay: int = 3600
    recovery_rate: int = 2

class ScoringRuleCreate(ScoringRuleBase):
    pass

class ScoringRuleUpdate(BaseModel):
    score_impact: Optional[int] = None
    severity: Optional[str] = None
    is_enabled: Optional[bool] = None
    repeated_threshold: Optional[int] = None
    time_window: Optional[int] = None
    recovery_delay: Optional[int] = None
    recovery_rate: Optional[int] = None

class ScoringRuleResponse(ScoringRuleBase):
    id: int

    class Config:
        from_attributes = True
