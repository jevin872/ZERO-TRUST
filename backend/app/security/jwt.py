from datetime import datetime, timedelta, timezone
from typing import List, Optional
import jwt
from jwt import PyJWTError
from app.config import settings

ALGORITHM = "HS256"

def create_access_token(
    user_id: int, 
    session_id: str, 
    roles: List[str], 
    expires_delta: Optional[timedelta] = None
) -> str:
    to_encode = {
        "sub": str(user_id),
        "session_id": session_id,
        "roles": roles,
        "type": "access"
    }
    
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.JWT_ACCESS_EXPIRE_MINUTES)
        
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(
    user_id: int, 
    expires_delta: Optional[timedelta] = None
) -> str:
    to_encode = {
        "sub": str(user_id),
        "type": "refresh"
    }
    
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=settings.JWT_REFRESH_EXPIRE_DAYS)
        
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[ALGORITHM])
        return payload
    except PyJWTError:
        return None
