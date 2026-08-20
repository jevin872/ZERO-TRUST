from sqlalchemy.orm import Session
from app.database.connection import engine, Base
from app.models.organization import Organization
from app.models.role import Role
from app.models.scoring_rule import ScoringRule
from app.models.risk_policy import RiskPolicy

# Ensure all models are imported so SQLAlchemy metadata registers them
from app.models import (
    User, Session as UserSession, Device, SecurityEvent, 
    TrustScore, TrustScoreHistory, Threat, AuditLog, MFARecord, AdministrativeAction
)

def init_db(db: Session) -> None:
    # 1. Create all tables if they don't exist
    Base.metadata.create_all(bind=engine)

    # 2. Seed Organizations
    orgs = [
        {"id": "DEMO_BANK", "name": "ZeroTrust Simulated Bank", "industry": "Finance"},
        {"id": "HOSPITAL", "name": "Metro Health Medical Center", "industry": "Healthcare"}
    ]
    for org_data in orgs:
        org_exists = db.query(Organization).filter(Organization.id == org_data["id"]).first()
        if not org_exists:
            new_org = Organization(**org_data)
            db.add(new_org)
    db.commit()

    # 3. Seed Roles
    roles = ["USER", "ADMIN"]
    for role_name in roles:
        role_exists = db.query(Role).filter(Role.name == role_name).first()
        if not role_exists:
            new_role = Role(name=role_name)
            db.add(new_role)
    db.commit()

    # 4. Seed Default Scoring Rules per Organization
    rules_bank = [
        # Positive conditions
        {"event_type": "LOGIN_SUCCESS", "score_impact": 2, "severity": "LOW", "repeated_threshold": 1, "time_window": 300},
        {"event_type": "MFA_SUCCESS", "score_impact": 5, "severity": "LOW", "repeated_threshold": 1, "time_window": 300},
        {"event_type": "NORMAL_VERIFIED_ACTIVITY", "score_impact": 2, "severity": "LOW", "repeated_threshold": 1, "time_window": 300, "recovery_delay": 3600, "recovery_rate": 2},
        {"event_type": "SCORE_RECOVERY", "score_impact": 2, "severity": "LOW", "repeated_threshold": 1, "time_window": 300},
        
        # Negative conditions
        {"event_type": "LOGIN_FAILURE", "score_impact": -10, "severity": "MEDIUM", "repeated_threshold": 3, "time_window": 300},
        {"event_type": "MULTIPLE_LOGIN_FAILURE", "score_impact": -20, "severity": "HIGH", "repeated_threshold": 1, "time_window": 300},
        {"event_type": "MFA_FAILURE", "score_impact": -15, "severity": "HIGH", "repeated_threshold": 3, "time_window": 300},
        {"event_type": "NEW_DEVICE", "score_impact": -5, "severity": "LOW", "repeated_threshold": 1, "time_window": 300},
        {"event_type": "UNKNOWN_DEVICE", "score_impact": -10, "severity": "MEDIUM", "repeated_threshold": 1, "time_window": 300},
        {"event_type": "NEW_IP", "score_impact": -5, "severity": "LOW", "repeated_threshold": 1, "time_window": 300},
        {"event_type": "FREQUENT_IP_CHANGE", "score_impact": -15, "severity": "HIGH", "repeated_threshold": 2, "time_window": 600},
        {"event_type": "EXCESSIVE_API_REQUESTS", "score_impact": -15, "severity": "MEDIUM", "repeated_threshold": 10, "time_window": 60},
        {"event_type": "UNAUTHORIZED_RESOURCE_ACCESS", "score_impact": -15, "severity": "HIGH", "repeated_threshold": 3, "time_window": 300},
        {"event_type": "REPEATED_UNAUTHORIZED_ACCESS", "score_impact": -25, "severity": "CRITICAL", "repeated_threshold": 1, "time_window": 300},
        {"event_type": "SUSPICIOUS_ACTIVITY", "score_impact": -15, "severity": "MEDIUM", "repeated_threshold": 1, "time_window": 300},
        {"event_type": "LARGE_TRANSACTION", "score_impact": -20, "severity": "HIGH", "repeated_threshold": 1, "time_window": 300},
        {"event_type": "SENSITIVE_PROFILE_CHANGE", "score_impact": -20, "severity": "HIGH", "repeated_threshold": 1, "time_window": 300},
        {"event_type": "SESSION_IDLE", "score_impact": -5, "severity": "LOW", "repeated_threshold": 1, "time_window": 300},
        
        # Log session states
        {"event_type": "SESSION_CREATED", "score_impact": 0, "severity": "LOW", "repeated_threshold": 1, "time_window": 300},
        {"event_type": "SESSION_TERMINATED", "score_impact": 0, "severity": "LOW", "repeated_threshold": 1, "time_window": 300},
    ]

    rules_hospital = [
        {"event_type": "LOGIN_SUCCESS", "score_impact": 2, "severity": "LOW", "repeated_threshold": 1, "time_window": 300},
        {"event_type": "MFA_SUCCESS", "score_impact": 5, "severity": "LOW", "repeated_threshold": 1, "time_window": 300},
        {"event_type": "NORMAL_VERIFIED_ACTIVITY", "score_impact": 2, "severity": "LOW", "repeated_threshold": 1, "time_window": 300, "recovery_delay": 1800, "recovery_rate": 3},
        {"event_type": "LOGIN_FAILURE", "score_impact": -10, "severity": "MEDIUM", "repeated_threshold": 3, "time_window": 300},
        {"event_type": "MFA_FAILURE", "score_impact": -15, "severity": "HIGH", "repeated_threshold": 3, "time_window": 300},
        {"event_type": "UNKNOWN_WORKSTATION", "score_impact": -15, "severity": "HIGH", "repeated_threshold": 1, "time_window": 300},
        {"event_type": "PATIENT_RECORD_ACCESS", "score_impact": -25, "severity": "CRITICAL", "repeated_threshold": 1, "time_window": 300},
        {"event_type": "AFTER_HOURS_ACCESS", "score_impact": -10, "severity": "MEDIUM", "repeated_threshold": 1, "time_window": 300},
    ]

    # Seed rules for DEMO_BANK
    for r in rules_bank:
        exists = db.query(ScoringRule).filter(
            ScoringRule.organization_id == "DEMO_BANK",
            ScoringRule.event_type == r["event_type"]
        ).first()
        if not exists:
            new_rule = ScoringRule(organization_id="DEMO_BANK", **r)
            db.add(new_rule)

    # Seed rules for HOSPITAL
    for r in rules_hospital:
        exists = db.query(ScoringRule).filter(
            ScoringRule.organization_id == "HOSPITAL",
            ScoringRule.event_type == r["event_type"]
        ).first()
        if not exists:
            new_rule = ScoringRule(organization_id="HOSPITAL", **r)
            db.add(new_rule)

    db.commit()

    # 5. Seed Default Risk Policies for Organizations
    default_policies = [
        {"risk_level": "LOW", "enforced_action": "ALLOW_ACCESS"},
        {"risk_level": "MEDIUM_LOW", "enforced_action": "INCREASE_MONITORING"},
        {"risk_level": "MEDIUM_HIGH", "enforced_action": "REQUIRE_MFA"},
        {"risk_level": "HIGH", "enforced_action": "RESTRICT_SENSITIVE_OPERATIONS"},
        {"risk_level": "CRITICAL", "enforced_action": "TERMINATE_SESSION_AND_BLOCK"}
    ]

    for org_id in ["DEMO_BANK", "HOSPITAL"]:
        for policy in default_policies:
            exists = db.query(RiskPolicy).filter(
                RiskPolicy.organization_id == org_id,
                RiskPolicy.risk_level == policy["risk_level"]
            ).first()
            if not exists:
                new_policy = RiskPolicy(
                    organization_id=org_id,
                    risk_level=policy["risk_level"],
                    enforced_action=policy["enforced_action"],
                    is_enabled=True
                )
                db.add(new_policy)
                
    db.commit()
