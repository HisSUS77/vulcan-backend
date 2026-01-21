'// lets you define interfaces without implementation'
from typing import Protocol, Any

class GraphEngine(Protocol):
    def build_ast(self, scan_id: str, file_id: str) -> dict[str, Any]:
        ...

    def build_cfg(self, scan_id: str, file_id: str) -> dict[str, Any]:
        ...

    def build_dfg(self, scan_id: str, file_id: str) -> dict[str, Any]:
        ...
