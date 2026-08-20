import pyotp
import qrcode
import base64
from io import BytesIO
from app.config import settings

def generate_totp_secret() -> str:
    return pyotp.random_base32()

def get_totp_uri(secret: str, username: str) -> str:
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=settings.MFA_ISSUER)

def generate_qr_code_base64(provisioning_uri: str) -> str:
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{img_str}"

def verify_totp_token(secret: str, token: str) -> bool:
    totp = pyotp.TOTP(secret)
    # Allows a grace period of 1 interval before and after
    return totp.verify(token, valid_window=1)
