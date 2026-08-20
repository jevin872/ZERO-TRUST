from pydantic import BaseModel
from datetime import datetime
from typing import List, Optional

class TrustScoreResponse(BaseModel):
    user_id: int
    current_score: int
    risk_level: str
    last_updated: datetime

    class Config:
        from_attributes = True

class ExplainableFactor(BaseModel):
    event: str
    impact: int
    reason: str

class ExplainableTrustScoreResponse(BaseModel):
    trust_score: int
    risk_level: str
    decision: str
    factors: List[ExplainableFactor]
