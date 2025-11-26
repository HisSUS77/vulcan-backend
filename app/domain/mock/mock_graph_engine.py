import random


class MockGraphEngine:
    def _build(self, graph_type: str, scan_id: str, file_id: str):
        nodes = [
            {"id": "n1", "label": "Function foo", "severity": random.choice(["LOW", "MEDIUM", "HIGH"])},
            {"id": "n2", "label": "If condition", "severity": random.choice(["LOW", "MEDIUM"])},
        ]
        edges = [{"from": "n1", "to": "n2"}]
        return {"type": graph_type, "nodes": nodes, "edges": edges, "meta": {"file": f"src/{file_id}.py"}}

    def build_ast(self, scan_id: str, file_id: str):
        return self._build("AST", scan_id, file_id)

    def build_cfg(self, scan_id: str, file_id: str):
        return self._build("CFG", scan_id, file_id)

    def build_dfg(self, scan_id: str, file_id: str):
        return self._build("DFG", scan_id, file_id)
