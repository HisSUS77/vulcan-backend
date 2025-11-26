from typing import Protocol, Any


class PatchGenerator(Protocol):
    def generate_patch(self, vulnerability_id: int, options: dict | None = None) -> dict:
        ...

    def regenerate_patch(self, patch_id: int) -> dict:
        ...
