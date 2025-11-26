from typing import Dict
import difflib

from app.domain.mock.mock_patch_generator import MockPatchGenerator


class PatchService:
    def __init__(self) -> None:
        self.generator = MockPatchGenerator()
        self.store: Dict[int, dict] = {}

    def list_vulnerabilities(self, scan_id: str) -> list[dict]:
        return [
            {"id": 1, "vuln_id": "v-1", "severity": "MEDIUM", "title": "Unsanitized input", "file_path": "src/app.py"},
            {"id": 2, "vuln_id": "v-2", "severity": "HIGH", "title": "SQL Injection", "file_path": "src/db.py"},
        ]

    def generate(self, vulnerability_id: int, options: dict | None = None) -> dict:
        patch = self.generator.generate_patch(vulnerability_id, options)
        self.store[patch["id"]] = patch
        return patch

    def get(self, patch_id: int) -> dict | None:
        return self.store.get(patch_id)

    def export(self, patch_id: int) -> dict:
        patch = self.store.get(patch_id)
        if not patch:
            return {"detail": "Not found"}
        diff = difflib.unified_diff(
            patch["original_code"].splitlines(),
            patch["patched_code"].splitlines(),
            fromfile="original.py",
            tofile="patched.py",
            lineterm="",
        )
        content = "\n".join(diff) or "(no diff)"
        return {"filename": f"patch-{patch_id}.diff", "content": content}

    def apply(self, patch_id: int) -> dict:
        patch = self.store.get(patch_id)
        if not patch:
            return {"detail": "Not found"}
        patch["status"] = "APPLIED"
        return {"status": "APPLIED", "branch": f"vulcan-fix-{patch_id}"}

    def regenerate(self, patch_id: int) -> dict:
        new_patch = self.generator.regenerate_patch(patch_id)
        self.store[new_patch["id"]] = new_patch
        return {"patch_id": new_patch["id"], "version": "latest"}
