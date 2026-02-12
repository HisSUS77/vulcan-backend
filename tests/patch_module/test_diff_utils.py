import pytest

from app.patch_module.diff_utils import parse_unified_diff, PatchValidationError, normalize_diff_text


VALID_DIFF = """--- a/app.py
+++ b/app.py
@@ -1,2 +1,2 @@
-print("bad")
+print("good")
"""


def test_valid_diff():
    summary = parse_unified_diff(VALID_DIFF)
    assert summary.target_file.endswith("app.py")
    assert summary.added_lines == 1
    assert summary.removed_lines == 1


def test_multi_file_diff_rejected():
    diff = """--- a/a.py
+++ b/a.py
@@ -1 +1 @@
-a
+b
--- a/b.py
+++ b/b.py
@@ -1 +1 @@
-a
+b
"""
    with pytest.raises(PatchValidationError):
        parse_unified_diff(diff)


def test_no_hunks_rejected():
    diff = """--- a/a.py
+++ b/a.py
"""
    with pytest.raises(PatchValidationError):
        parse_unified_diff(diff)


def test_markdown_fenced_diff():
    diff = """```diff
--- a/a.py
+++ b/a.py
@@ -1 +1 @@
-a
+b
```"""
    summary = parse_unified_diff(diff)
    assert summary.target_file.endswith("a.py")
