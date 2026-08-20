import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from sqlalchemy.orm import Session as DBSession

from app.models.session import Session as UserSession
from app.models.device import Device
from app.database.redis_conn import redis_client
from app.security.jwt import create_refresh_token

class SessionService:
    @staticmethod
    def create_session(
        db: DBSession, 
        user_id: int, 
        ip_address: str, 
        user_agent: Optional[str], 
        device_fingerprint: str
    ) -> UserSession:
        session_id = str(uuid.uuid4())
        
        # Calculate session expiry (e.g. 24 hours)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        
        # Generate a refresh token for this session
        refresh_token = create_refresh_token(user_id=user_id)
        
        # Create session database record
        db_session = UserSession(
            id=session_id,
            user_id=user_id,
            refresh_token=refresh_token,
            ip_address=ip_address,
            user_agent=user_agent,
            is_active=True,
            expires_at=expires_at.replace(tzinfo=None) # store naive datetime in DB
        )
        db.add(db_session)
        db.commit()
        db.refresh(db_session)
        
        # Store active session status in cache (Redis)
        cache_key = f"session:{session_id}"
        redis_client.set(cache_key, "active", ex=24 * 3600)
        
        # Handle device fingerprinting
        device = db.query(Device).filter(
            Device.user_id == user_id,
            Device.device_fingerprint == device_fingerprint
        ).first()
        
        if not device:
            # First time seeing this device
            device = Device(
                user_id=user_id,
                device_fingerprint=device_fingerprint,
                is_trusted=False
            )
            db.add(device)
            db.commit()
            db.refresh(device)
            
        return db_session

    @staticmethod
    def is_session_valid(db: DBSession, session_id: str) -> bool:
        # Check cache first
        cache_key = f"session:{session_id}"
        cached_status = redis_client.get(cache_key)
        
        if cached_status == "active":
            return True
        if cached_status == "terminated":
            return False
            
        # Fallback to Database
        db_session = db.query(UserSession).filter(UserSession.id == session_id).first()
        if not db_session or not db_session.is_active:
            redis_client.set(cache_key, "terminated", ex=3600)
            return False
            
        # Check expiry
        if db_session.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
            db_session.is_active = False
            db.commit()
            redis_client.set(cache_key, "terminated", ex=3600)
            return False
            
        # Re-populate cache
        redis_client.set(cache_key, "active", ex=3600)
        return True

    @staticmethod
    def terminate_session(db: DBSession, session_id: str) -> bool:
        # Update cache
        cache_key = f"session:{session_id}"
        redis_client.set(cache_key, "terminated", ex=3600)
        
        # Update database
        db_session = db.query(UserSession).filter(UserSession.id == session_id).first()
        if db_session:
            db_session.is_active = False
            db_session.refresh_token = None # Clear refresh token
            db.commit()
            return True
        return False

    @staticmethod
    def terminate_all_user_sessions(db: DBSession, user_id: int) -> int:
        db_sessions = db.query(UserSession).filter(
            UserSession.user_id == user_id,
            UserSession.is_active == True
        ).all()
        
        count = 0
        for db_session in db_sessions:
            db_session.is_active = False
            db_session.refresh_token = None
            cache_key = f"session:{db_session.id}"
            redis_client.set(cache_key, "terminated", ex=3600)
            count += 1
            
        db.commit()
        return count

    @staticmethod
    def get_active_sessions(db: DBSession, user_id: int) -> List[UserSession]:
        # Sync expired ones
        now_naive = datetime.now()
        expired_sessions = db.query(UserSession).filter(
            UserSession.user_id == user_id,
            UserSession.is_active == True,
            UserSession.expires_at < now_naive
        ).all()
        
        for sess in expired_sessions:
            sess.is_active = False
            redis_client.set(f"session:{sess.id}", "terminated", ex=3600)
        if expired_sessions:
            db.commit()
            
        return db.query(UserSession).filter(
            UserSession.user_id == user_id,
            UserSession.is_active == True
        ).all()
