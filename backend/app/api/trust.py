from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from app.database.connection import get_db
from app.schemas.score import ExplainableTrustScoreResponse, ExplainableFactor, TrustScoreResponse
from app.schemas.event import SecurityEventResponse
from app.security.permissions import RoleChecker
from app.models.user import User
from app.models.security_event import SecurityEvent
from app.scoring.trust_engine import TrustEngine
from app.scoring.policy_engine import PolicyEngine

router = APIRouter(tags=["Trust Scoring"])

# Admin Only check dependency
admin_required = RoleChecker(["ADMIN"])

@router.get("/admin/users/{user_id}/trust-score", response_model=ExplainableTrustScoreResponse)
def get_user_trust_score_admin(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(admin_required)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
        
    score_record = TrustEngine.get_or_create_trust_score(db, user_id)
    policy = PolicyEngine.evaluate_policy(db, user_id, score_record.current_score)
    
    recent_events = db.query(SecurityEvent).filter(
        SecurityEvent.user_id == user_id,
        SecurityEvent.score_change != 0
    ).order_by(SecurityEvent.timestamp.desc()).limit(15).all()
    
    factors = [
        ExplainableFactor(
            event=event.event_type,
            impact=event.score_change,
            reason=event.explainable_reason
        )
        for event in recent_events
    ]
    
    return ExplainableTrustScoreResponse(
        trust_score=score_record.current_score,
        risk_level=policy["risk_level"],
        decision=policy["action"],
        factors=factors
    )

@router.get("/admin/users/{user_id}/trust-history", response_model=List[SecurityEventResponse])
def get_user_trust_history_admin(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(admin_required)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
        
    return db.query(SecurityEvent).filter(
        SecurityEvent.user_id == user_id
    ).order_by(SecurityEvent.timestamp.desc()).all()
