class NotificationService:
    def list(self, page: int = 1, size: int = 10):
        total = 25
        items = [
            {"id": i, "message": f"Scan {i} completed", "level": "INFO", "created_at": "2025-11-01T10:00:00Z"}
            for i in range((page - 1) * size + 1, min(page * size + 1, total + 1))
        ]
        return {"items": items, "page": page, "size": size, "total": total}
