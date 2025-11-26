import random
import time


class MockPatchGenerator:
    def __init__(self):
        self._counter = 100

    def generate_patch(self, vulnerability_id: int, options: dict | None = None) -> dict:
        self._counter += 1
        original = "password = request.args['pwd']"
        patched = "pwd = request.get('pwd'); assert isinstance(pwd, str)\npassword = pwd"  # simplified
        return {
            "id": self._counter,
            "scan_id": "demo-scan",
            "vuln_id": f"v-{vulnerability_id}",
            "original_code": original,
            "patched_code": patched,
            "explanation": "Fixes CWE-20: Improper Input Validation. Sanitizes user input.",
            "confidence": round(random.uniform(0.75, 0.9), 2),
            "status": "GENERATED",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    def regenerate_patch(self, patch_id: int) -> dict:
        return self.generate_patch(patch_id)
