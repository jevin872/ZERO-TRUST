from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.database.connection import get_db
from app.models.user import User
from app.models.session import Session as UserSession
from app.security.jwt import decode_token

security = HTTPBearer()

def get_token_payload(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    token = credentials.credentials
    payload = decode_token(token)
    if not payload or payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload

def get_current_user(payload: dict = Depends(get_token_payload), db: Session = Depends(get_db)) -> User:
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )
    
    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
        
    # Check if user is blocked
    if user.is_blocked:
        if user.blocked_until and user.blocked_until > datetime.now():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"User account is temporarily blocked until {user.blocked_until.isoformat()}",
            )
        else:
            # Block expired, unblock them
            user.is_blocked = False
            user.blocked_until = None
            db.commit()
            
    return user

def get_current_session(payload: dict = Depends(get_token_payload), db: Session = Depends(get_db)) -> UserSession:
    session_id = payload.get("session_id")
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session ID missing from token",
        )
        
    user_session = db.query(UserSession).filter(UserSession.id == session_id).first()
    if not user_session or not user_session.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session is inactive or terminated",
        )
        
    if user_session.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        user_session.is_active = False
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired",
        )
        
    return user_session

class RoleChecker:
    def __init__(self, allowed_roles: list[str]):
        self.allowed_roles = allowed_roles

    def __call__(self, user: User = Depends(get_current_user)) -> User:
        user_role_names = [role.name for role in user.roles]
        if not any(role in self.allowed_roles for role in user_role_names):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions to access this resource",
            )
        return user
