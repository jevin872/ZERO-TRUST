from sqlalchemy.orm import Session
from datetime import datetime, timezone
from fastapi import HTTPException, status

from app.models.user import User
from app.models.mfa import MFARecord
from app.security.password import verify_password
from app.security.mfa import generate_totp_secret, get_totp_uri, generate_qr_code_base64, verify_totp_token
from app.database.redis_conn import redis_client
from app.services.security_event_service import SecurityEventService

class AuthenticationService:
    @staticmethod
    def authenticate_user(
        db: Session, 
        username: str, 
        password: str,
        ip_address: str,
        user_agent: str,
        device_fingerprint: str
    ) -> User:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
            )
            
        # Check if user is blocked
        if user.is_blocked:
            if user.blocked_until and user.blocked_until > datetime.now():
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Account is temporarily blocked. Please try again after {user.blocked_until.isoformat()}",
                )
            else:
                user.is_blocked = False
                user.blocked_until = None
                db.commit()

        # Verify password
        if not verify_password(password, user.hashed_password):
            # Log login failure in cache (Redis)
            fail_key = f"login_failures:{user.id}"
            failures = redis_client.incr(fail_key)
            if failures == 1:
                redis_client.expire(fail_key, 300) # 5 minutes window
                
            # Log LOGIN_FAILURE security event
            SecurityEventService.log_event(
                db=db,
                user_id=user.id,
                event_type="LOGIN_FAILURE",
                ip_address=ip_address,
                device_info=user_agent[:255]
            )
            
            # Check for multiple login failures escalation
            if failures >= 3:
                SecurityEventService.log_event(
                    db=db,
                    user_id=user.id,
                    event_type="MULTIPLE_LOGIN_FAILURE",
                    ip_address=ip_address,
                    device_info=user_agent[:255]
                )
                
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
            )
            
        # Success - clear failures
        redis_client.delete(f"login_failures:{user.id}")
        return user

    @staticmethod
    def setup_mfa(db: Session, user: User) -> dict:
        mfa_rec = db.query(MFARecord).filter(MFARecord.user_id == user.id).first()
        
        if not mfa_rec:
            # Generate new secret
            secret = generate_totp_secret()
            mfa_rec = MFARecord(user_id=user.id, secret_key=secret, is_enabled=False)
            db.add(mfa_rec)
            db.commit()
            db.refresh(mfa_rec)
        elif mfa_rec.is_enabled:
            # MFA already set up and enabled
            return {
                "secret_key": mfa_rec.secret_key,
                "qr_code_base64": "",
                "is_enabled": True
            }
            
        # Generate QR code URI
        provisioning_uri = get_totp_uri(mfa_rec.secret_key, user.username)
        qr_code_base64 = generate_qr_code_base64(provisioning_uri)
        
        return {
            "secret_key": mfa_rec.secret_key,
            "qr_code_base64": qr_code_base64,
            "is_enabled": False
        }

    @staticmethod
    def verify_mfa(
        db: Session, 
        user: User, 
        token: str, 
        ip_address: str, 
        user_agent: str,
        session_id: str = None
    ) -> bool:
        mfa_rec = db.query(MFARecord).filter(MFARecord.user_id == user.id).first()
        if not mfa_rec:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA is not set up for this user."
            )

        if not verify_totp_token(mfa_rec.secret_key, token):
            # Log MFA_FAILURE security event
            SecurityEventService.log_event(
                db=db,
                user_id=user.id,
                event_type="MFA_FAILURE",
                ip_address=ip_address,
                device_info=user_agent[:255],
                session_id=session_id
            )
            return False

        # If not enabled, enable it now
        if not mfa_rec.is_enabled:
            mfa_rec.is_enabled = True
            db.commit()

        # Log MFA_SUCCESS security event
        SecurityEventService.log_event(
            db=db,
            user_id=user.id,
            event_type="MFA_SUCCESS",
            ip_address=ip_address,
            device_info=user_agent[:255],
            session_id=session_id
        )
        return True
