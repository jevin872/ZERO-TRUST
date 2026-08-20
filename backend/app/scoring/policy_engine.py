from sqlalchemy.orm import Session as DBSession
from app.models.user import User
from app.models.risk_policy import RiskPolicy
from app.scoring.risk_engine import RiskEngine

class PolicyEngine:
    @staticmethod
    def evaluate_policy(db: DBSession, user_id: int, score: int) -> dict:
        """
        Evaluates the security policy dynamically by fetching organization-specific rules from the DB.
        """
        # 1. Fetch user to find organization ID
        user = db.query(User).filter(User.id == user_id).first()
        org_id = user.organization_id if user else "DEMO_BANK"

        # 2. Classify risk level
        risk_level = RiskEngine.classify_risk(score)

        # 3. Query dynamic policy from database
        policy = db.query(RiskPolicy).filter(
            RiskPolicy.organization_id == org_id,
            RiskPolicy.risk_level == risk_level,
            RiskPolicy.is_enabled == True
        ).first()

        if policy:
            action = policy.enforced_action
        else:
            # Fallback hardcoded defaults if no DB policy exists
            fallback_actions = {
                "LOW": "ALLOW_ACCESS",
                "MEDIUM_LOW": "INCREASE_MONITORING",
                "MEDIUM_HIGH": "REQUIRE_MFA",
                "HIGH": "RESTRICT_SENSITIVE_OPERATIONS",
                "CRITICAL": "TERMINATE_SESSION_AND_BLOCK"
            }
            action = fallback_actions.get(risk_level, "ALLOW_ACCESS")

        descriptions = {
            "ALLOW_ACCESS": "Allow normal activity and transactions.",
            "INCREASE_MONITORING": "Active monitoring of security signals and transactional behaviors.",
            "REQUIRE_MFA": "Require multi-factor authentication challenge verification.",
            "RESTRICT_SENSITIVE_OPERATIONS": "Block sensitive actions such as adding beneficiaries or transfers.",
            "TERMINATE_SESSION_AND_BLOCK": "Terminate sessions immediately and block account."
        }

        return {
            "risk_level": risk_level,
            "action": action,
            "description": descriptions.get(action, "No action required.")
        }
