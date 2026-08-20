from pydantic import BaseModel
from typing import Optional

class LoginRequest(BaseModel):
    username: str
    password: str
    device_fingerprint: Optional[str] = "unknown_device"

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    mfa_required: bool = False

class MFASetupResponse(BaseModel):
    secret_key: str
    qr_code_base64: str # Base64 data URI of QR code image
    is_enabled: bool

class MFAVerifyRequest(BaseModel):
    token: str # The 6-digit TOTP code

class TokenPayload(BaseModel):
    sub: Optional[str] = None
    exp: Optional[int] = None
    session_id: Optional[str] = None
    roles: Optional[list] = []
