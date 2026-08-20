from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from typing import List

from app.database.connection import get_db
from app.schemas.event import SecurityEventCreate, SecurityEventResponse
from app.security.permissions import get_current_user, get_current_session, RoleChecker
from app.models.user import User
from app.models.session import Session as UserSession
from app.models.security_event import SecurityEvent
from app.services.security_event_service import SecurityEventService

router = APIRouter(tags=["Security Events"])

@router.post("/security-events", response_model=SecurityEventResponse)
def create_security_event(
    request: Request,
    event_data: SecurityEventCreate,
    current_user: User = Depends(get_current_user),
    current_session: UserSession = Depends(get_current_session),
    db: Session = Depends(get_db)
):
    ip_address = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "unknown")
    
    try:
        event = SecurityEventService.log_event(
            db=db,
            user_id=current_user.id,
            event_type=event_data.event_type,
            ip_address=ip_address,
            device_info=user_agent[:255],
            session_id=current_session.id
        )
        return event
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.get("/users/me/security-events", response_model=List[SecurityEventResponse])
def get_my_security_events(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return db.query(SecurityEvent).filter(
        SecurityEvent.user_id == current_user.id
    ).order_by(SecurityEvent.timestamp.desc()).all()

@router.get("/admin/security-events", response_model=List[SecurityEventResponse])
def get_all_security_events_admin(
    db: Session = Depends(get_db),
    admin: User = Depends(RoleChecker(["ADMIN"]))
):
    return db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).all()
