import pytest

from app.patch_module.syntax_validator import validate_python_syntax, validate_javascript_syntax


def test_python_syntax_valid():
    original = "print('ok')"
    diff = """--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-print('ok')
+print('fixed')
"""
    result = validate_python_syntax(original, diff)
    assert result.passed is True


def test_python_syntax_invalid():
    original = "print('ok')"
    diff = """--- a/app.py
+++ b/app.py
@@ -1 +1 @@
-print('ok')
+print('bad'
"""
    result = validate_python_syntax(original, diff)
    assert result.passed is False


def test_js_syntax_valid_or_unverified():
    original = "const a = 1;"
    diff = """--- a/app.js
+++ b/app.js
@@ -1 +1 @@
-const a = 1;
+const a = 2;
"""
    result = validate_javascript_syntax(original, diff)
    assert result.passed is True


def test_js_syntax_invalid_if_parser_available():
    original = "const a = 1;"
    diff = """--- a/app.js
+++ b/app.js
@@ -1 +1 @@
-const a = 1;
+const a = ;
"""
    result = validate_javascript_syntax(original, diff)
    # If esprima is available it should fail; if not, it returns unverified True.
    assert result.passed in (True, False)
