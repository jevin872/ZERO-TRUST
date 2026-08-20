from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from datetime import datetime, timezone, timedelta

from app.database.connection import get_db
from app.schemas.auth import LoginRequest, TokenResponse, MFASetupResponse, MFAVerifyRequest
from app.schemas.user import UserCreate, UserResponse
from app.services.user_service import UserService
from app.services.authentication_service import AuthenticationService
from app.services.session_service import SessionService
from app.services.security_event_service import SecurityEventService
from app.security.jwt import create_access_token, decode_token
from app.security.permissions import get_current_user, get_current_session
from app.models.user import User
from app.models.session import Session as UserSession
from app.models.device import Device

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user_in: UserCreate, db: Session = Depends(get_db)):
    try:
        user = UserService.create_user(db, user_in)
        return user
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e)
        )

@router.post("/login", response_model=TokenResponse)
def login(
    request: Request,
    login_data: LoginRequest,
    db: Session = Depends(get_db)
):
    ip_address = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "unknown")
    
    # 1. Authenticate username and password (handles login failures & account locking)
    user = AuthenticationService.authenticate_user(
        db=db,
        username=login_data.username,
        password=login_data.password,
        ip_address=ip_address,
        user_agent=user_agent,
        device_fingerprint=login_data.device_fingerprint
    )
    
    # 2. Check if MFA is enabled
    mfa_enabled = user.mfa_record is not None and user.mfa_record.is_enabled
    
    # 3. Create session
    session = SessionService.create_session(
        db=db,
        user_id=user.id,
        ip_address=ip_address,
        user_agent=user_agent,
        device_fingerprint=login_data.device_fingerprint
    )
    
    # Log LOGIN_SUCCESS
    SecurityEventService.log_event(
        db=db,
        user_id=user.id,
        event_type="LOGIN_SUCCESS",
        ip_address=ip_address,
        device_info=user_agent[:255],
        session_id=session.id
    )

    # 4. Check device fingerprint to see if it is a new/unknown device
    device_exists = db.query(Device).filter(
        Device.user_id == user.id,
        Device.device_fingerprint == login_data.device_fingerprint,
        Device.is_trusted == True
    ).first()
    
    if not device_exists:
        # Trigger organization-specific unknown device/workstation event
        event_type = "UNKNOWN_DEVICE"
        if user.organization_id == "HOSPITAL":
            event_type = "UNKNOWN_WORKSTATION"
            
        SecurityEventService.log_event(
            db=db,
            user_id=user.id,
            event_type=event_type,
            ip_address=ip_address,
            device_info=user_agent[:255],
            session_id=session.id
        )

    # 5. Check IP change
    # Retrieve user's previous sessions to see if IP is different from last active session
    prev_session = db.query(UserSession).filter(
        UserSession.user_id == user.id,
        UserSession.id != session.id
    ).order_by(UserSession.created_at.desc()).first()
    
    if prev_session and prev_session.ip_address != ip_address:
        # Trigger NEW_IP event
        SecurityEventService.log_event(
            db=db,
            user_id=user.id,
            event_type="NEW_IP",
            ip_address=ip_address,
            device_info=user_agent[:255],
            session_id=session.id
        )
        
        # Check for frequent IP changes in the last 10 minutes
        ten_minutes_ago = datetime.utcnow() - timedelta(minutes=10)
        unique_ips = db.query(UserSession.ip_address).filter(
            UserSession.user_id == user.id,
            UserSession.created_at >= ten_minutes_ago
        ).distinct().count()
        
        if unique_ips >= 2:
            SecurityEventService.log_event(
                db=db,
                user_id=user.id,
                event_type="FREQUENT_IP_CHANGE",
                ip_address=ip_address,
                device_info=user_agent[:255],
                session_id=session.id
            )

    # 6. Generate access token
    roles = [role.name for role in user.roles]
    access_token = create_access_token(
        user_id=user.id,
        session_id=session.id,
        roles=roles
    )
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=session.refresh_token,
        mfa_required=mfa_enabled
    )

@router.post("/mfa/setup", response_model=MFASetupResponse)
def setup_mfa(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    mfa_details = AuthenticationService.setup_mfa(db, current_user)
    return mfa_details

@router.post("/mfa/verify", response_model=dict)
def verify_mfa(
    request: Request,
    verify_data: MFAVerifyRequest,
    current_user: User = Depends(get_current_user),
    current_session: UserSession = Depends(get_current_session),
    db: Session = Depends(get_db)
):
    ip_address = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "unknown")
    
    verified = AuthenticationService.verify_mfa(
        db=db,
        user=current_user,
        token=verify_data.token,
        ip_address=ip_address,
        user_agent=user_agent,
        session_id=current_session.id
    )
    
    if not verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid MFA verification code."
        )
        
    return {"message": "MFA verification successful."}

@router.post("/refresh", response_model=TokenResponse)
def refresh(
    refresh_token: str,
    db: Session = Depends(get_db)
):
    # Decode refresh token
    payload = decode_token(refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
        
    user_id = payload.get("sub")
    # Verify session is still active and has this refresh token
    session = db.query(UserSession).filter(
        UserSession.user_id == int(user_id),
        UserSession.refresh_token == refresh_token,
        UserSession.is_active == True
    ).first()
    
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session not found or expired"
        )
        
    # Verify session validity (expiry check)
    if session.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        session.is_active = False
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired"
        )
        
    user = session.user
    roles = [role.name for role in user.roles]
    
    new_access_token = create_access_token(
        user_id=user.id,
        session_id=session.id,
        roles=roles
    )
    
    return TokenResponse(
        access_token=new_access_token,
        refresh_token=refresh_token,
        mfa_required=False
    )

@router.post("/logout", status_code=status.HTTP_200_OK)
def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    current_session: UserSession = Depends(get_current_session),
    db: Session = Depends(get_db)
):
    ip_address = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "unknown")
    
    # Deactivate session
    SessionService.terminate_session(db, current_session.id)
    
    # Log session termination
    SecurityEventService.log_event(
        db=db,
        user_id=current_user.id,
        event_type="SESSION_TERMINATED",
        ip_address=ip_address,
        device_info=user_agent[:255],
        session_id=current_session.id
    )
    
    return {"detail": "Successfully logged out."}
