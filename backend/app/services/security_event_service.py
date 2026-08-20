from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session as DBSession

from app.models.user import User
from app.models.security_event import SecurityEvent
from app.models.trust_score import TrustScore
from app.models.scoring_rule import ScoringRule
from app.models.threat import Threat
from app.models.audit_log import AuditLog
from app.scoring.trust_engine import TrustEngine
from app.scoring.policy_engine import PolicyEngine
from app.services.session_service import SessionService
from app.services.websocket_manager import manager

class SecurityEventService:
    @staticmethod
    def log_event(
        db: DBSession,
        user_id: int,
        event_type: str,
        ip_address: str,
        device_info: str,
        session_id: str = None
    ) -> SecurityEvent:
        # 1. Fetch user to ensure validity
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise ValueError(f"User with id {user_id} does not exist.")

        org_id = user.organization_id

        # 2. Fetch the corresponding scoring rule for severity
        rule = db.query(ScoringRule).filter(
            ScoringRule.organization_id == org_id,
            ScoringRule.event_type == event_type,
            ScoringRule.is_enabled == True
        ).first()
        severity = rule.severity if rule else "LOW"

        # 3. Calculate score change through Trust Engine
        # (This updates the trust_scores table internally and commits)
        previous_score, score_change, new_score, explainable_reason = TrustEngine.calculate_score_change(
            db=db,
            user_id=user_id,
            event_type=event_type
        )

        # 4. Evaluate Policy based on new score (Dynamic DB Lookup)
        policy_decision = PolicyEngine.evaluate_policy(db, user_id, new_score)
        risk_level = policy_decision["risk_level"]
        action_taken = policy_decision["action"]

        # Update running risk level in the trust score table
        score_record = TrustEngine.get_or_create_trust_score(db, user_id)
        score_record.risk_level = risk_level
        db.commit()

        # 5. Automatically create Threats for HIGH or CRITICAL issues
        if severity in ["HIGH", "CRITICAL"] or risk_level in ["HIGH", "CRITICAL"]:
            # Prevent logging identical unresolved threats multiple times
            existing_threat = db.query(Threat).filter(
                Threat.user_id == user_id,
                Threat.event_type == event_type,
                Threat.is_resolved == False
            ).first()
            if not existing_threat:
                threat = Threat(
                    user_id=user_id,
                    event_type=event_type,
                    severity=severity,
                    description=explainable_reason,
                    is_resolved=False
                )
                db.add(threat)
                db.commit()

        # 6. Handle Adaptive Control Actions
        if action_taken == "TERMINATE_SESSION_AND_BLOCK":
            # Terminate all active sessions
            terminated_count = SessionService.terminate_all_user_sessions(db, user_id)
            
            # Temporarily block user for 15 minutes
            block_duration = timedelta(minutes=15)
            blocked_until = datetime.now() + block_duration
            
            user.is_blocked = True
            user.blocked_until = blocked_until
            db.commit()

            # Create an audit log record
            audit = AuditLog(
                actor_username="SYSTEM",
                target_username=user.username,
                action="BLOCK_USER",
                ip_address=ip_address,
                reason=f"Trust Score dropped to {new_score} (CRITICAL). Triggered by {event_type}. Terminated {terminated_count} sessions."
            )
            db.add(audit)
            db.commit()

        # 7. Create and store the Security Event log
        db_event = SecurityEvent(
            user_id=user_id,
            session_id=session_id,
            organization_id=org_id,
            event_type=event_type,
            severity=severity,
            ip_address=ip_address,
            device_info=device_info,
            previous_trust_score=previous_score,
            score_change=score_change,
            new_trust_score=new_score,
            risk_level=risk_level,
            action_taken=action_taken,
            explainable_reason=explainable_reason
        )
        db.add(db_event)
        db.commit()
        db.refresh(db_event)

        # 8. Broadcast Event to Connected Admin Dashboard WebSockets
        event_payload = {
            "type": "SECURITY_EVENT",
            "event": {
                "id": db_event.id,
                "user_id": user_id,
                "username": user.username,
                "event_type": event_type,
                "severity": severity,
                "previous_trust_score": previous_score,
                "score_change": score_change,
                "new_trust_score": new_score,
                "risk_level": risk_level,
                "action_taken": action_taken,
                "explainable_reason": explainable_reason,
                "timestamp": db_event.timestamp.isoformat() if db_event.timestamp else datetime.now().isoformat()
            }
        }
        manager.broadcast_sync(event_payload)

        return db_event

    @staticmethod
    def log_recovery_event(
        db: DBSession,
        user_id: int,
        ip_address: str,
        device_info: str
    ) -> SecurityEvent | None:
        """Attempts recovery and logs event if recovery happened."""
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return None
            
        did_recover, prev_score, new_score = TrustEngine.process_recovery(db, user_id)
        if not did_recover:
            return None

        policy_decision = PolicyEngine.evaluate_policy(db, user_id, new_score)
        risk_level = policy_decision["risk_level"]
        action_taken = policy_decision["action"]

        # Update running risk level
        score_record = TrustEngine.get_or_create_trust_score(db, user_id)
        score_record.risk_level = risk_level
        db.commit()

        db_event = SecurityEvent(
            user_id=user_id,
            session_id=None,
            organization_id=user.organization_id,
            event_type="SCORE_RECOVERY",
            severity="LOW",
            ip_address=ip_address,
            device_info=device_info,
            previous_trust_score=prev_score,
            score_change=new_score - prev_score,
            new_trust_score=new_score,
            risk_level=risk_level,
            action_taken=action_taken,
            explainable_reason=f"Trust score gradually recovered by +{new_score - prev_score} points due to sustained normal activity."
        )
        db.add(db_event)
        db.commit()
        db.refresh(db_event)

        # Broadcast Recovery Event
        event_payload = {
            "type": "SECURITY_EVENT",
            "event": {
                "id": db_event.id,
                "user_id": user_id,
                "username": user.username,
                "event_type": "SCORE_RECOVERY",
                "severity": "LOW",
                "previous_trust_score": prev_score,
                "score_change": new_score - prev_score,
                "new_trust_score": new_score,
                "risk_level": risk_level,
                "action_taken": action_taken,
                "explainable_reason": db_event.explainable_reason,
                "timestamp": db_event.timestamp.isoformat() if db_event.timestamp else datetime.now().isoformat()
            }
        }
        manager.broadcast_sync(event_payload)

        return db_event
