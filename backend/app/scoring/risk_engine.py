class RiskEngine:
    @staticmethod
    def classify_risk(score: int) -> str:
        """
        Classifies trust scores (0-100) into risk categories:
        - 80 - 100: LOW
        - 60 - 79: MEDIUM_LOW
        - 40 - 59: MEDIUM_HIGH
        - 20 - 39: HIGH
        - 0 - 19: CRITICAL
        """
        if score >= 80:
            return "LOW"
        elif score >= 60:
            return "MEDIUM_LOW"
        elif score >= 40:
            return "MEDIUM_HIGH"
        elif score >= 20:
            return "HIGH"
        else:
            return "CRITICAL"
