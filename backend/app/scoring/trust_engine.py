from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session as DBSession
from app.models.user import User
from app.models.trust_score import TrustScore, TrustScoreHistory
from app.models.scoring_rule import ScoringRule
from app.models.security_event import SecurityEvent

class TrustEngine:
    @staticmethod
    def get_or_create_trust_score(db: DBSession, user_id: int) -> TrustScore:
        score_record = db.query(TrustScore).filter(TrustScore.user_id == user_id).first()
        if not score_record:
            score_record = TrustScore(
                user_id=user_id,
                current_score=100,
                risk_level="LOW"
            )
            db.add(score_record)
            db.commit()
            db.refresh(score_record)
        return score_record

    @staticmethod
    def calculate_score_change(
        db: DBSession, 
        user_id: int, 
        event_type: str
    ) -> tuple[int, int, int, str]:
        """
        Calculates the score change based on organization-specific scoring rules.
        Returns: (previous_score, score_change, new_score, explainable_reason)
        """
        # 1. Fetch user to find organization ID
        user = db.query(User).filter(User.id == user_id).first()
        org_id = user.organization_id if user else "DEMO_BANK"

        # 2. Fetch current score
        score_record = TrustEngine.get_or_create_trust_score(db, user_id)
        previous_score = score_record.current_score

        # 3. Fetch organization-specific rule
        rule = db.query(ScoringRule).filter(
            ScoringRule.organization_id == org_id,
            ScoringRule.event_type == event_type,
            ScoringRule.is_enabled == True
        ).first()

        if not rule:
            return previous_score, 0, previous_score, f"No active scoring rules defined for event '{event_type}'."

        base_impact = rule.score_impact
        reason = f"Event '{event_type}' occurred."

        # 4. Repeated event logic (escalation)
        if base_impact < 0 and rule.repeated_threshold > 1:
            time_cutoff = datetime.now() - timedelta(seconds=rule.time_window)
            recent_events_count = db.query(SecurityEvent).filter(
                SecurityEvent.user_id == user_id,
                SecurityEvent.event_type == event_type,
                SecurityEvent.timestamp >= time_cutoff
            ).count()

            if recent_events_count >= rule.repeated_threshold - 1:
                # Apply 1.5x multiplier for consecutive violations
                escalated_impact = int(base_impact * 1.5)
                reason = f"Repeated event '{event_type}' (Triggered {recent_events_count + 1} times inside {rule.time_window}s window). Escalated penalty applied."
                base_impact = escalated_impact

        new_score = previous_score + base_impact
        new_score = max(0, min(100, new_score))
        actual_change = new_score - previous_score

        # Update current score record in database
        score_record.current_score = new_score
        db.commit()

        # Log change in trust_score_history table
        if actual_change != 0:
            history_record = TrustScoreHistory(
                user_id=user_id,
                previous_score=previous_score,
                new_score=new_score,
                score_change=actual_change,
                event_type=event_type
            )
            db.add(history_record)
            db.commit()

        return previous_score, actual_change, new_score, reason

    @staticmethod
    def process_recovery(db: DBSession, user_id: int) -> tuple[bool, int, int]:
        """
        Attempts score recovery for the user based on organization recovery rules.
        """
        user = db.query(User).filter(User.id == user_id).first()
        org_id = user.organization_id if user else "DEMO_BANK"

        score_record = TrustEngine.get_or_create_trust_score(db, user_id)
        if score_record.current_score >= 100:
            return False, 100, 100

        # Find recovery rule config
        recovery_rule = db.query(ScoringRule).filter(
            ScoringRule.organization_id == org_id,
            ScoringRule.event_type == "NORMAL_VERIFIED_ACTIVITY",
            ScoringRule.is_enabled == True
        ).first()

        recovery_delay = recovery_rule.recovery_delay if recovery_rule else 3600
        recovery_rate = recovery_rule.recovery_rate if recovery_rule else 2

        # Check last negative event
        last_negative_event = db.query(SecurityEvent).filter(
            SecurityEvent.user_id == user_id,
            SecurityEvent.score_change < 0
        ).order_by(SecurityEvent.timestamp.desc()).first()

        if last_negative_event:
            seconds_since_incident = (datetime.now() - last_negative_event.timestamp).total_seconds()
            if seconds_since_incident < recovery_delay:
                return False, score_record.current_score, score_record.current_score

        # Throttle recovery to once per minute
        last_recovery = db.query(SecurityEvent).filter(
            SecurityEvent.user_id == user_id,
            SecurityEvent.event_type == "SCORE_RECOVERY"
        ).order_by(SecurityEvent.timestamp.desc()).first()

        if last_recovery:
            if (datetime.now() - last_recovery.timestamp).total_seconds() < 60:
                return False, score_record.current_score, score_record.current_score

        previous_score = score_record.current_score
        new_score = min(100, previous_score + recovery_rate)
        actual_change = new_score - previous_score
        
        if actual_change > 0:
            score_record.current_score = new_score
            db.commit()
            
            # Log history
            history_record = TrustScoreHistory(
                user_id=user_id,
                previous_score=previous_score,
                new_score=new_score,
                score_change=actual_change,
                event_type="SCORE_RECOVERY"
            )
            db.add(history_record)
            db.commit()
            return True, previous_score, new_score

        return False, previous_score, new_score
