import unittest
import tempfile
from pathlib import Path

from app.domain.analysis.multi_file_repo_graph import MultiFileRepositoryGraph
from _utils import has_grammar


class TestTSExportEquals(unittest.TestCase):
    def test_ts_export_equals_import_equals(self):
        if not has_grammar("typescript"):
            self.skipTest("Tree-sitter TypeScript grammar not available")
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = Path(tmpdir)
            (repo / "a.ts").write_text("const value = 1;\\nexport = value;", encoding="utf-8")
            (repo / "b.ts").write_text("import x = require('./a');\\nconsole.log(x);", encoding="utf-8")
            graph = MultiFileRepositoryGraph(str(repo)).build()
            imports = sum(len(m.imports) for m in graph["modules"])
            exports = sum(len(m.exports) for m in graph["modules"])
            self.assertGreaterEqual(imports, 1)
            self.assertGreaterEqual(exports, 1)


if __name__ == "__main__":
    unittest.main()
