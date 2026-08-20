from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime, timedelta

from app.database.connection import get_db
from app.models.user import User
from app.models.session import Session as UserSession
from app.models.scoring_rule import ScoringRule
from app.models.risk_policy import RiskPolicy
from app.models.threat import Threat
from app.models.audit_log import AuditLog
from app.models.trust_score import TrustScore
from app.schemas.user import UserResponse
from app.schemas.rule import ScoringRuleResponse, ScoringRuleCreate, ScoringRuleUpdate
from app.schemas.audit import AuditLogResponse
from app.security.permissions import RoleChecker
from app.services.session_service import SessionService
from app.services.security_event_service import SecurityEventService

router = APIRouter(prefix="/admin", tags=["Admin Operations"])

# Admin Only check dependency
admin_required = RoleChecker(["ADMIN"])

class SimulationRequest(BaseModel):
    user_id: int
    event_type: str
    ip_address: Optional[str] = "127.0.0.1"
    device_info: Optional[str] = "Simulated Device"

class TerminateUserSessionRequest(BaseModel):
    session_id: str

@router.get("/dashboard", response_model=dict)
def get_admin_dashboard_stats(
    db: Session = Depends(get_db),
    admin: User = Depends(admin_required)
):
    total_users = db.query(User).count()
    active_sessions = db.query(UserSession).filter(UserSession.is_active == True).count()
    recently_blocked = db.query(User).filter(User.is_blocked == True).count()
    threat_count = db.query(Threat).filter(Threat.is_resolved == False).count()

    # Risk level counts
    low_risk = db.query(TrustScore).filter(TrustScore.risk_level == "LOW").count()
    med_low = db.query(TrustScore).filter(TrustScore.risk_level == "MEDIUM_LOW").count()
    med_high = db.query(TrustScore).filter(TrustScore.risk_level == "MEDIUM_HIGH").count()
    high_risk = db.query(TrustScore).filter(TrustScore.risk_level == "HIGH").count()
    critical_risk = db.query(TrustScore).filter(TrustScore.risk_level == "CRITICAL").count()

    return {
        "total_users": total_users,
        "active_sessions": active_sessions,
        "recently_blocked": recently_blocked,
        "unresolved_threats": threat_count,
        "risk_distribution": {
            "LOW": low_risk,
            "MEDIUM_LOW": med_low,
            "MEDIUM_HIGH": med_high,
            "HIGH": high_risk,
            "CRITICAL": critical_risk
        }
    }

@router.get("/users", response_model=List[UserResponse])
def get_all_users(
    db: Session = Depends(get_db),
    admin: User = Depends(admin_required)
):
    return db.query(User).all()

@router.get("/threats", response_model=List[dict])
def get_threats(
    db: Session = Depends(get_db),
    admin: User = Depends(admin_required)
):
    threats = db.query(Threat).order_by(Threat.timestamp.desc()).all()
    # Serialize with username for admin clarity
    serialized = []
    for t in threats:
        serialized.append({
            "id": t.id,
            "user_id": t.user_id,
            "username": t.user.username,
            "event_type": t.event_type,
            "severity": t.severity,
            "description": t.description,
            "is_resolved": t.is_resolved,
            "timestamp": t.timestamp.isoformat()
        })
    return serialized

@router.post("/users/{user_id}/block", response_model=dict)
def block_user_admin(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(admin_required)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    if user.is_blocked:
        return {"message": "User is already blocked."}
        
    user.is_blocked = True
    user.blocked_until = datetime.now() + timedelta(days=365)
    
    # Terminate user sessions
    terminated_count = SessionService.terminate_all_user_sessions(db, user_id)
    
    # Log administrative action
    ip_address = request.client.host if request.client else "127.0.0.1"
    audit = AuditLog(
        actor_username=admin.username,
        target_username=user.username,
        action="BLOCK_USER",
        ip_address=ip_address,
        reason=f"Administrative block. Active sessions terminated ({terminated_count})."
    )
    db.add(audit)
    db.commit()
    
    return {"message": f"User {user.username} blocked and {terminated_count} sessions terminated."}

@router.post("/users/{user_id}/unblock", response_model=dict)
def unblock_user_admin(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(admin_required)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    if not user.is_blocked:
        return {"message": "User is not blocked."}
        
    user.is_blocked = False
    user.blocked_until = None
    
    # Log administrative action
    ip_address = request.client.host if request.client else "127.0.0.1"
    audit = AuditLog(
        actor_username=admin.username,
        target_username=user.username,
        action="UNBLOCK_USER",
        ip_address=ip_address,
        reason="Administrative unblock."
    )
    db.add(audit)
    db.commit()
    
    return {"message": f"User {user.username} unblocked successfully."}

@router.post("/users/{user_id}/terminate-session", response_model=dict)
def terminate_user_session_admin(
    user_id: int,
    req_body: TerminateUserSessionRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(admin_required)
):
    # Verify session exists
    session = db.query(UserSession).filter(
        UserSession.id == req_body.session_id,
        UserSession.user_id == user_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found for this user.")

    SessionService.terminate_session(db, session.id)

    # Log action
    ip_address = request.client.host if request.client else "127.0.0.1"
    audit = AuditLog(
        actor_username=admin.username,
        target_username=session.user.username,
        action="TERMINATE_SESSION",
        ip_address=ip_address,
        reason=f"Administrative eviction of session ID {session.id[:8]}..."
    )
    db.add(audit)
    db.commit()

    return {"message": "Session terminated successfully."}

@router.get("/scoring-rules", response_model=List[ScoringRuleResponse])
def get_scoring_rules_admin(
    db: Session = Depends(get_db),
    admin: User = Depends(admin_required)
):
    return db.query(ScoringRule).all()

@router.post("/scoring-rules", response_model=ScoringRuleResponse, status_code=status.HTTP_201_CREATED)
def create_scoring_rule_admin(
    rule_data: ScoringRuleCreate,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(admin_required)
):
    rule = ScoringRule(**rule_data.model_dump())
    db.add(rule)
    db.commit()
    db.refresh(rule)
    
    # Log action
    ip_address = request.client.host if request.client else "127.0.0.1"
    audit = AuditLog(
        actor_username=admin.username,
        action="CREATE_SCORING_RULE",
        ip_address=ip_address,
        reason=f"Created scoring rule for {rule.event_type}."
    )
    db.add(audit)
    db.commit()
    
    return rule

@router.put("/scoring-rules/{rule_id}", response_model=ScoringRuleResponse)
def update_scoring_rule_admin(
    rule_id: int,
    rule_data: ScoringRuleUpdate,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(admin_required)
):
    rule = db.query(ScoringRule).filter(ScoringRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Scoring rule not found.")
        
    for key, value in rule_data.model_dump(exclude_unset=True).items():
        setattr(rule, key, value)
        
    db.commit()
    db.refresh(rule)
    
    # Log action
    ip_address = request.client.host if request.client else "127.0.0.1"
    audit = AuditLog(
        actor_username=admin.username,
        action="UPDATE_SCORING_RULE",
        ip_address=ip_address,
        reason=f"Modified scoring rule id {rule_id} ({rule.event_type})."
    )
    db.add(audit)
    db.commit()
    
    return rule

@router.post("/simulate", response_model=dict)
def simulate_event_admin(
    sim_data: SimulationRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(admin_required)
):
    user = db.query(User).filter(User.id == sim_data.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
        
    # Get active session ID if exists to bind
    active_sess = db.query(UserSession).filter(
        UserSession.user_id == sim_data.user_id,
        UserSession.is_active == True
    ).first()
    session_id = active_sess.id if active_sess else None

    # Trigger telemetry event logging (which recalculates score, risk, and policy)
    event = SecurityEventService.log_event(
        db=db,
        user_id=sim_data.user_id,
        event_type=sim_data.event_type,
        ip_address=sim_data.ip_address,
        device_info=sim_data.device_info,
        session_id=session_id
    )

    return {
        "success": True,
        "event_id": event.id,
        "previous_trust_score": event.previous_trust_score,
        "new_trust_score": event.new_trust_score,
        "score_change": event.score_change,
        "risk_level": event.risk_level,
        "action_taken": event.action_taken
    }

@router.get("/audit-logs", response_model=List[AuditLogResponse])
def get_audit_logs(
    db: Session = Depends(get_db),
    admin: User = Depends(admin_required)
):
    return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).all()
