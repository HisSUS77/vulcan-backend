from app.domain.mock.mock_graph_engine import MockGraphEngine


class GraphService:
    def __init__(self) -> None:
        self.engine = MockGraphEngine()

    def graph(self, scan_id: str, file_id: str, gtype: str) -> dict:
        if gtype == "AST":
            return self.engine.build_ast(scan_id, file_id)
        if gtype == "CFG":
            return self.engine.build_cfg(scan_id, file_id)
        if gtype == "DFG":
            return self.engine.build_dfg(scan_id, file_id)
        return {"detail": "Unsupported graph type"}
