from typing import Protocol, Any


class AnalyzerEngine(Protocol):
    def analyze(self, repo_id: int, branch: str, mode: str) -> dict[str, Any]:
        ...
