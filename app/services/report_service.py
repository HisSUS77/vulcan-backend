class ReportService:
    def list(self, repo_id: int | None = None, date_from: str | None = None, date_to: str | None = None, tag: str | None = None):
        return [
            {
                "id": 12,
                "repo_id": 1,
                "scan_id": "ae12f",
                "created_at": "2025-11-01T10:05:00Z",
                "total_vulns": 25,
                "critical": 1,
                "high": 5,
                "medium": 11,
                "low": 8,
                "ai_accuracy": 0.81,
                "compliance_flags": {"OWASP_TOP10": True, "CWE_25": True},
            }
        ]

    def get(self, report_id: int):
        return {
            "id": report_id,
            "summary": {
                "total_vulns": 25,
                "critical": 1,
                "high": 5,
                "medium": 11,
                "low": 8,
                "ai_accuracy": 0.81,
            },
            "vulnerabilities": [
                {"id": 1, "title": "SQL Injection", "severity": "HIGH"},
                {"id": 2, "title": "XSS", "severity": "MEDIUM"},
            ],
            "insights": {"top_paths": 3, "fix_rate": 0.6},
        }

    def export(self, report_id: int, fmt: str):
        if fmt == "json":
            return self.get(report_id)
        if fmt == "csv":
            return {"content": "id,title,severity\n1,SQL Injection,HIGH"}
        if fmt == "pdf":
            return {"content": f"PDF report {report_id} (stub)"}
        return {"detail": "Unsupported format"}

    def compare(self, report_id_1: int, report_id_2: int):
        return {
            "report_1": self.get(report_id_1)["summary"],
            "report_2": self.get(report_id_2)["summary"],
            "diff": {"improved": 5, "regressed": 2},
        }
