import unittest
import tempfile
from pathlib import Path

from app.domain.analysis.multi_file_repo_graph import MultiFileRepositoryGraph
from _utils import has_grammar


class TestReexportChain(unittest.TestCase):
    def test_reexport_chain(self):
        if not has_grammar("javascript"):
            self.skipTest("Tree-sitter JavaScript grammar not available")
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            (repo / "a.js").write_text("export const a = 1;", encoding="utf-8")
            (repo / "b.js").write_text("export * from './a';", encoding="utf-8")
            (repo / "c.js").write_text("export * from './b';", encoding="utf-8")

            graph = MultiFileRepositoryGraph(str(repo)).build()
            # c.js should see a reexported symbol eventually
            c_module = next((m for m in graph["modules"] if m.file_path.endswith("c.js")), None)
            self.assertIsNotNone(c_module)
            self.assertTrue(any(e.name == "a" for e in c_module.exports))


if __name__ == "__main__":
    unittest.main()
