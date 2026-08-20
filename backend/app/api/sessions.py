from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel

from app.database.connection import get_db
from app.schemas.session import SessionResponse
from app.security.permissions import get_current_user, get_current_session, RoleChecker
from app.models.user import User
from app.models.session import Session as UserSession
from app.services.session_service import SessionService

router = APIRouter(tags=["Sessions"])

class TerminateSessionRequest(BaseModel):
    session_id: str

@router.post("/session/validate", response_model=dict)
def validate_session(
    current_session: UserSession = Depends(get_current_session)
):
    return {
        "valid": True,
        "session_id": current_session.id,
        "expires_at": current_session.expires_at.isoformat()
    }

@router.post("/session/terminate", response_model=dict)
def terminate_session(
    term_request: TerminateSessionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    session_to_term = db.query(UserSession).filter(
        UserSession.id == term_request.session_id
    ).first()
    
    if not session_to_term:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
        
    # Check ownership
    is_admin = any(role.name == "ADMIN" for role in current_user.roles)
    if session_to_term.user_id != current_user.id and not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to terminate this session."
        )
        
    terminated = SessionService.terminate_session(db, term_request.session_id)
    if not terminated:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to terminate session"
        )
        
    return {"message": "Session terminated successfully."}

@router.get("/sessions", response_model=List[SessionResponse])
def get_my_sessions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return SessionService.get_active_sessions(db, current_user.id)

@router.get("/admin/sessions", response_model=List[SessionResponse])
def get_all_active_sessions_admin(
    db: Session = Depends(get_db),
    admin: User = Depends(RoleChecker(["ADMIN"]))
):
    # Retrieve all active sessions
    return db.query(UserSession).filter(UserSession.is_active == True).all()
