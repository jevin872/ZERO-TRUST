import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Use an in-memory SQLite database for testing.
# StaticPool prevents SQLite from closing the in-memory database when the connection closes.
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Monkeypatch the database connection module to redirect all SessionLocal calls to TestingSessionLocal
import app.database.connection as db_conn
db_conn.SessionLocal = TestingSessionLocal
db_conn.engine = engine

# Now import main app and other components
from fastapi.testclient import TestClient
from app.database.init_db import init_db
from app.database.connection import get_db
from app.main import app

@pytest.fixture(name="db_session", scope="function")
def fixture_db_session():
    # Create tables and seed data
    Base = db_conn.Base
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    init_db(db)
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)

@pytest.fixture(name="client", scope="function")
def fixture_client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass
            
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
