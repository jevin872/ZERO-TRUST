import pyotp
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

from app.models.user import User
from app.models.role import Role
from app.models.security_event import SecurityEvent
from app.models.trust_score import TrustScore
from app.models.scoring_rule import ScoringRule
from app.models.audit_log import AuditLog
from app.models.session import Session as UserSession
from app.models.bank import BankAccount, BankTransaction, BankBeneficiary
from app.services.session_service import SessionService
from app.scoring.policy_engine import PolicyEngine

def test_user_registration(client: TestClient, db_session: Session):
    response = client.post(
        "/api/v1/auth/register",
        json={"username": "alice", "email": "alice@company.com", "password": "securepassword", "organization_id": "DEMO_BANK"}
    )
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "alice"
    assert data["email"] == "alice@company.com"
    assert data["is_blocked"] is False

    # Check database status
    db_user = db_session.query(User).filter(User.username == "alice").first()
    assert db_user is not None
    assert len(db_user.roles) == 1
    assert db_user.roles[0].name == "USER"
    
    # Check initial trust score is 100
    score_record = db_session.query(TrustScore).filter(TrustScore.user_id == db_user.id).first()
    assert score_record is not None
    assert score_record.current_score == 100

    # Check simulated bank account is auto-created with balance $12,450.82
    bank_acct = db_session.query(BankAccount).filter(BankAccount.user_id == db_user.id).first()
    assert bank_acct is not None
    assert bank_acct.balance == 12450.82
    assert bank_acct.account_number.startswith("ACT-")

def test_login_success_and_unknown_device_penalty(client: TestClient, db_session: Session):
    client.post(
        "/api/v1/auth/register",
        json={"username": "bob", "email": "bob@company.com", "password": "password123", "organization_id": "DEMO_BANK"}
    )

    # Login with a random device fingerprint -> should trigger UNKNOWN_DEVICE event, dropping score to 90
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "bob", "password": "password123", "device_fingerprint": "unseen_device_fp"}
    )
    assert response.status_code == 200
    tokens = response.json()
    assert "access_token" in tokens
    assert tokens["mfa_required"] is False

    # Verify score dropped to 90 (100 - 10 for UNKNOWN_DEVICE)
    db_user = db_session.query(User).filter(User.username == "bob").first()
    score_record = db_session.query(TrustScore).filter(TrustScore.user_id == db_user.id).first()
    assert score_record.current_score == 90

def test_failed_login_degradation(client: TestClient, db_session: Session):
    client.post(
        "/api/v1/auth/register",
        json={"username": "charlie", "email": "charlie@company.com", "password": "password123", "organization_id": "DEMO_BANK"}
    )

    # Failed login 1 -> -10 (score = 90)
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "charlie", "password": "wrongpassword"}
    )
    assert response.status_code == 401
    
    db_user = db_session.query(User).filter(User.username == "charlie").first()
    score_rec = db_session.query(TrustScore).filter(TrustScore.user_id == db_user.id).first()
    assert score_rec.current_score == 90

    # Failed login 2 -> -10 (score = 80)
    client.post(
        "/api/v1/auth/login",
        json={"username": "charlie", "password": "wrongpassword"}
    )
    
    # Failed login 3 -> -10, but crosses repeated failure threshold of 3 attempts, triggering MULTIPLE_LOGIN_FAILURE (-20)
    # Total drops: -10 (login failure) and -20 (escalated penalty).
    # Expected score: 80 - 10 - 20 = 50.
    client.post(
        "/api/v1/auth/login",
        json={"username": "charlie", "password": "wrongpassword"}
    )
    
    assert score_rec.current_score == 50

def test_unauthorized_access_trap(client: TestClient, db_session: Session):
    client.post(
        "/api/v1/auth/register",
        json={"username": "david", "email": "david@company.com", "password": "password123", "organization_id": "DEMO_BANK"}
    )

    # Login to get JWT
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username": "david", "password": "password123", "device_fingerprint": "dev1"}
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Attempt to hit admin users list -> should fail with 403 as user lacks ADMIN role
    res = client.get("/api/v1/admin/users", headers=headers)
    assert res.status_code == 403

    # Hitting admin route should trigger UNAUTHORIZED_RESOURCE_ACCESS (-15)
    # Score should drop from 90 (100 - 10 unknown device) to 75
    db_user = db_session.query(User).filter(User.username == "david").first()
    score_rec = db_session.query(TrustScore).filter(TrustScore.user_id == db_user.id).first()
    assert score_rec.current_score == 75

def test_critical_score_session_termination_and_blocking(client: TestClient, db_session: Session):
    client.post(
        "/api/v1/auth/register",
        json={"username": "eve", "email": "eve@company.com", "password": "password123", "organization_id": "DEMO_BANK"}
    )

    # Login (initial score = 90 due to unknown device)
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username": "eve", "password": "password123", "device_fingerprint": "dev_eve"}
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Verify session is active in database
    db_user = db_session.query(User).filter(User.username == "eve").first()
    sessions = db_session.query(UserSession).filter(UserSession.user_id == db_user.id).all()
    assert len(sessions) == 1
    assert sessions[0].is_active is True

    # Drop score to CRITICAL (<20) by injecting repeated suspicious events
    # Hitting admin route 4 consecutive times:
    # Attempt 1: 90 -> 75
    # Attempt 2: 75 -> 60
    # Attempt 3: 60 -> 45
    # Attempt 4: 45 -> 30
    for _ in range(4):
        client.get("/api/v1/admin/users", headers=headers)

    # Attempt 5: 30 -> 15 (Critical!). Should immediately trigger session termination and block account!
    res = client.get("/api/v1/admin/users", headers=headers)
    
    # Reload database objects (clear SQLAlchemy cache)
    db_session.expire_all()
    db_session.refresh(db_user)
    assert db_user.is_blocked is True
    assert db_user.blocked_until > datetime.now()

    # Sessions must be invalidated
    sessions = db_session.query(UserSession).filter(UserSession.user_id == db_user.id).all()
    assert all(s.is_active is False for s in sessions)

    # Subsequent requests with same token should be rejected as user is blocked (returns 403)
    res = client.get("/api/v1/users/me", headers=headers)
    assert res.status_code == 403

def test_mfa_flow(client: TestClient, db_session: Session):
    client.post(
        "/api/v1/auth/register",
        json={"username": "frank", "email": "frank@company.com", "password": "password123", "organization_id": "DEMO_BANK"}
    )

    # Login
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username": "frank", "password": "password123", "device_fingerprint": "dev_frank"}
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Verify score is 90 (unknown device penalty)
    db_user = db_session.query(User).filter(User.username == "frank").first()
    score_rec = db_session.query(TrustScore).filter(TrustScore.user_id == db_user.id).first()
    assert score_rec.current_score == 90

    # Request MFA setup
    setup_res = client.post("/api/v1/auth/mfa/setup", headers=headers)
    assert setup_res.status_code == 200
    mfa_data = setup_res.json()
    assert "secret_key" in mfa_data
    assert "qr_code_base64" in mfa_data

    # Generate valid TOTP token
    totp = pyotp.TOTP(mfa_data["secret_key"])
    token_code = totp.now()

    # Verify MFA setup
    verify_res = client.post(
        "/api/v1/auth/mfa/verify",
        json={"token": token_code},
        headers=headers
    )
    assert verify_res.status_code == 200
    assert "successful" in verify_res.json()["message"].lower()

    # MFA verified should boost score by +5 points (90 -> 95)
    db_session.refresh(score_rec)
    assert score_rec.current_score == 95

def test_bank_transfers_and_restrictions(client: TestClient, db_session: Session):
    # Register user
    client.post(
        "/api/v1/auth/register",
        json={"username": "grace", "email": "grace@company.com", "password": "password123", "organization_id": "DEMO_BANK"}
    )
    db_user = db_session.query(User).filter(User.username == "grace").first()

    # Log in
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username": "grace", "password": "password123", "device_fingerprint": "grace_dev"}
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Add a beneficiary
    bene_res = client.post(
        "/api/v1/bank/beneficiaries",
        json={"name": "Alice Receiver", "account_number": "ACT-9876543210", "bank_name": "ZeroTrust Demo Bank"},
        headers=headers
    )
    assert bene_res.status_code == 200

    # Perform a standard simulated transfer ($100) -> should succeed
    tx_res = client.post(
        "/api/v1/bank/transfer",
        json={"amount": 100.00, "description": "Gift", "beneficiary_account_number": "ACT-9876543210"},
        headers=headers
    )
    assert tx_res.status_code == 200
    assert tx_res.json()["success"] is True
    assert tx_res.json()["new_balance"] == 12350.82

    # Perform a large simulated transfer ($6,000) -> triggers LARGE_TRANSACTION security penalty (-20 points!)
    # Score drops from 90 (100 - 10 unknown device) to 70 (Medium-Low Risk)
    tx_large_res = client.post(
        "/api/v1/bank/transfer",
        json={"amount": 6000.00, "description": "Car Purchase", "beneficiary_account_number": "ACT-9876543210"},
        headers=headers
    )
    assert tx_large_res.status_code == 200
    score_rec = db_session.query(TrustScore).filter(TrustScore.user_id == db_user.id).first()
    assert score_rec.current_score == 70
    assert score_rec.risk_level == "MEDIUM_LOW"

    # Trigger score degradation to HIGH risk (<40) by attempting unauthorized administrative routes
    # Hitting admin endpoint:
    # Attempt 1: 70 -> 55 (Medium-High)
    # Attempt 2: 55 -> 40 (Medium-High)
    # Attempt 3: 40 -> 25 (HIGH RISK!)
    for _ in range(3):
        client.get("/api/v1/admin/users", headers=headers)

    db_session.refresh(score_rec)
    assert score_rec.risk_level == "HIGH"

    # Try to execute another transfer when risk is HIGH -> should be blocked by PolicyEngine (returns 403)
    tx_blocked = client.post(
        "/api/v1/bank/transfer",
        json={"amount": 5.00, "description": "Tiny Transfer", "beneficiary_account_number": "ACT-9876543210"},
        headers=headers
    )
    assert tx_blocked.status_code == 403
    assert "blocked" in tx_blocked.json()["detail"].lower()

def test_organization_rule_isolation(client: TestClient, db_session: Session):
    # Register BANK user
    client.post(
        "/api/v1/auth/register",
        json={"username": "bank_user", "email": "bank_user@company.com", "password": "password123", "organization_id": "DEMO_BANK"}
    )
    
    # Register HOSPITAL user
    client.post(
        "/api/v1/auth/register",
        json={"username": "hospital_user", "email": "hospital_user@med.com", "password": "password123", "organization_id": "HOSPITAL"}
    )

    # Login BANK user -> unknown device penalty = -10 (score = 90)
    bank_login = client.post(
        "/api/v1/auth/login",
        json={"username": "bank_user", "password": "password123", "device_fingerprint": "dev_generic"}
    )
    bank_token = bank_login.json()["access_token"]
    db_session.expire_all()
    bank_usr = db_session.query(User).filter(User.username == "bank_user").first()
    bank_score = db_session.query(TrustScore).filter(TrustScore.user_id == bank_usr.id).first()
    assert bank_score.current_score == 90

    # Login HOSPITAL user -> unknown workstation penalty = -15 (score = 85)
    hospital_login = client.post(
        "/api/v1/auth/login",
        json={"username": "hospital_user", "password": "password123", "device_fingerprint": "dev_generic"}
    )
    hospital_token = hospital_login.json()["access_token"]
    db_session.expire_all()
    hosp_usr = db_session.query(User).filter(User.username == "hospital_user").first()
    hosp_score = db_session.query(TrustScore).filter(TrustScore.user_id == hosp_usr.id).first()
    
    # Check that hospital rules apply 15 point penalty instead of bank's 10 point penalty!
    # Initial score (100) - 15 (UNKNOWN_WORKSTATION) = 85.
    assert hosp_score.current_score == 85
