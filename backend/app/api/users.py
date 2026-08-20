from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from typing import List

from app.database.connection import get_db
from app.schemas.user import UserResponse
from app.schemas.event import SecurityEventResponse
from app.schemas.session import SessionResponse
from app.schemas.score import ExplainableTrustScoreResponse, ExplainableFactor
from app.security.permissions import get_current_user, get_current_session
from app.models.user import User
from app.models.session import Session as UserSession
from app.models.security_event import SecurityEvent
from app.scoring.trust_engine import TrustEngine
from app.scoring.policy_engine import PolicyEngine
from app.services.session_service import SessionService
from app.services.security_event_service import SecurityEventService

router = APIRouter(prefix="/users", tags=["Users"])

@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user

@router.get("/me/trust-score", response_model=ExplainableTrustScoreResponse)
def get_my_trust_score(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Attempt automatic recovery on request poll to gradually restore score
    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "unknown")
    SecurityEventService.log_recovery_event(db, current_user.id, client_ip, user_agent)

    # 1. Fetch current score record
    score_record = TrustEngine.get_or_create_trust_score(db, current_user.id)
    
    # 2. Evaluate policy
    policy = PolicyEngine.evaluate_policy(db, current_user.id, score_record.current_score)
    
    # 3. Pull recent negative or positive security events that influenced the score
    # We will look at events that occurred in the last 24 hours that changed the score
    recent_events = db.query(SecurityEvent).filter(
        SecurityEvent.user_id == current_user.id,
        SecurityEvent.score_change != 0
    ).order_by(SecurityEvent.timestamp.desc()).limit(10).all()
    
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

@router.get("/me/security-events", response_model=List[SecurityEventResponse])
def get_my_security_events(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return db.query(SecurityEvent).filter(
        SecurityEvent.user_id == current_user.id
    ).order_by(SecurityEvent.timestamp.desc()).all()

@router.get("/me/sessions", response_model=List[SessionResponse])
def get_my_sessions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return SessionService.get_active_sessions(db, current_user.id)
