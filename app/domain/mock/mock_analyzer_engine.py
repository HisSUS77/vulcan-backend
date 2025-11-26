import random


class MockAnalyzerEngine:
    def analyze(self, repo_id: int, branch: str, mode: str) -> dict:
        return {
            "severity": {
                "CRITICAL": random.randint(0, 2),
                "HIGH": random.randint(3, 8),
                "MEDIUM": random.randint(5, 15),
                "LOW": random.randint(5, 15),
            },
            "ai_confidence": round(random.uniform(0.7, 0.9), 2),
        }
