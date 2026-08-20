import time
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from app.database.redis_conn import redis_client
from app.database.connection import SessionLocal
from app.security.jwt import decode_token
from app.services.security_event_service import SecurityEventService

RATE_LIMIT_MAX_REQUESTS = 60 # requests
RATE_LIMIT_WINDOW = 60 # seconds

class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        client_ip = request.client.host if request.client else "127.0.0.1"
        
        # 1. Parse JWT to see if user is authenticated
        user_id = None
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            payload = decode_token(token)
            if payload:
                user_id = payload.get("sub")
        
        # Determine rate limit key
        identifier = f"user:{user_id}" if user_id else f"ip:{client_ip}"
        current_time = int(time.time())
        window_bucket = current_time // RATE_LIMIT_WINDOW
        cache_key = f"rate_limit:{identifier}:{window_bucket}"
        
        # Increment request count
        request_count = redis_client.incr(cache_key)
        if request_count == 1:
            redis_client.expire(cache_key, RATE_LIMIT_WINDOW)
            
        # 2. Check if rate limit is exceeded
        if request_count > RATE_LIMIT_MAX_REQUESTS:
            # If authenticated user, trigger EXCESSIVE_API_REQUESTS event
            if user_id:
                db = SessionLocal()
                try:
                    # Retrieve request session if available
                    session_id = payload.get("session_id")
                    user_agent = request.headers.get("user-agent", "unknown")
                    
                    # Create security event (which triggers scoring degradation)
                    SecurityEventService.log_event(
                        db=db,
                        user_id=int(user_id),
                        event_type="EXCESSIVE_API_REQUESTS",
                        ip_address=client_ip,
                        device_info=user_agent[:255],
                        session_id=session_id
                    )
                except Exception as e:
                    pass
                finally:
                    db.close()
                    
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Please slow down."}
            )
            
        return await call_next(request)
