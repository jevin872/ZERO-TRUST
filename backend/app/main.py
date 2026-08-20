import logging
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.config import settings
from app.database.connection import SessionLocal
from app.database.init_db import init_db
from app.services.websocket_manager import manager

# Import Middlewares
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.request_monitor import RequestMonitorMiddleware

# Import Routers
from app.api.auth import router as auth_router
from app.api.users import router as users_router
from app.api.trust import router as trust_router
from app.api.sessions import router as sessions_router
from app.api.security_events import router as events_router
from app.api.admin import router as admin_router
from app.api.bank import router as bank_router

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="ZeroTrustX & Simulated Bank API",
    description=(
        "FastAPI REST API implementing continuous authentication, dynamic trust scoring, "
        "and adaptive session protection for Simulated Banking operations."
    ),
    version="2.0.0",
)

# 1. CORS Configuration
origins = [
    settings.FRONTEND_URL,
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 2. Register Custom Middlewares
app.add_middleware(RequestMonitorMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

# 3. Include Routers under /api/v1
app.include_router(auth_router, prefix="/api/v1")
app.include_router(users_router, prefix="/api/v1")
app.include_router(trust_router, prefix="/api/v1")
app.include_router(sessions_router, prefix="/api/v1")
app.include_router(events_router, prefix="/api/v1")
app.include_router(admin_router, prefix="/api/v1")
app.include_router(bank_router, prefix="/api/v1")

# 4. WebSocket administrative alerts broadcast hub
@app.websocket("/api/v1/ws/admin")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Maintain active connection, waiting for client close
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)

@app.on_event("startup")
def on_startup():
    logger.info("Initializing database and seeding default values...")
    db = SessionLocal()
    try:
        init_db(db)
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
    finally:
        db.close()

@app.get("/", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "service": "zerotrustx-simulated-bank-api",
        "version": "2.0.0"
    }
