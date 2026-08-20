import logging
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from app.database.connection import SessionLocal
from app.security.jwt import decode_token
from app.services.security_event_service import SecurityEventService

logger = logging.getLogger(__name__)

class RequestMonitorMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        client_ip = request.client.host if request.client else "127.0.0.1"
        user_agent = request.headers.get("user-agent", "unknown")
        
        # Proceed with request
        response = await call_next(request)
        
        # Intercept 401/403 status codes to log unauthorized access
        if response.status_code in [401, 403]:
            # Try to identify the user from JWT
            user_id = None
            session_id = None
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]
                payload = decode_token(token)
                if payload:
                    user_id = payload.get("sub")
                    session_id = payload.get("session_id")
            
            if user_id:
                db = SessionLocal()
                try:
                    # Determine event type
                    event_type = "UNAUTHORIZED_RESOURCE_ACCESS"
                    
                    # Log event
                    SecurityEventService.log_event(
                        db=db,
                        user_id=int(user_id),
                        event_type=event_type,
                        ip_address=client_ip,
                        device_info=user_agent[:255],
                        session_id=session_id
                    )
                except Exception as e:
                    logger.error(f"Failed to log unauthorized access event: {e}")
                finally:
                    db.close()
                    
        return response
