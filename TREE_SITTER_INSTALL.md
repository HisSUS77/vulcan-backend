# Tree-sitter Universal Parser - Installation Guide

## Quick Start (5 Minutes)

```bash
# 1. Install tree-sitter
pip install tree-sitter

# 2. Build grammars
python setup_grammars.py

# 3. Test
python test_files/test_universal_parser.py

# 4. Done! 🎉
```

---

## Detailed Installation

### Prerequisites

#### Windows
- **Python 3.8+** - Already installed ✓
- **Git** - [Download](https://git-scm.com/downloads)
- **C Compiler** - Choose one:
  - Visual Studio Build Tools (Recommended)
  - MinGW-w64

**Install Visual Studio Build Tools:**
1. Download: https://visualstudio.microsoft.com/downloads/
2. Run installer
3. Select "Desktop development with C++"
4. Install (requires ~6GB)

**Or install MinGW:**
1. Download: https://www.mingw-w64.org/
2. Install and add to PATH

#### Linux (Ubuntu/Debian)
```bash
# Install build essentials
sudo apt update
sudo apt install build-essential git python3-pip

# Already have Python ✓
```

#### macOS
```bash
# Install Xcode Command Line Tools
xcode-select --install

# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

---

## Step-by-Step Installation

### Step 1: Install tree-sitter Python Package

```bash
pip install tree-sitter
```

**Verify:**
```bash
python -c "import tree_sitter; print('✓ tree-sitter installed')"
```

Expected output: `✓ tree-sitter installed`

---

### Step 2: Build Language Grammars

Navigate to your project directory:
```bash
cd c:\Users\huzai\Desktop\fyp\Vulcan\vulcan-backend\vulcan-backend
```

Run the setup script:
```bash
python setup_grammars.py
```

**What This Does:**
1. Clones Tree-sitter grammar repositories
2. Compiles them into `.so` files (or `.dll` on Windows)
3. Places them in `build/` directory

**Expected Output:**
```
=== Tree-sitter Grammar Setup ===

Checking requirements...
✓ tree-sitter Python package is installed
✓ git is installed
✓ C compiler (MSVC) is available

Repositories will be cloned to: ...\tree-sitter-repos
Grammars will be built to: ...\build

=== Cloning Language Repositories ===
Cloning python grammar...
✓ Cloned python successfully
Cloning javascript grammar...
✓ Cloned javascript successfully
...

=== Building Language Grammars ===
Building python grammar...
✓ Built python grammar successfully
Building javascript grammar...
✓ Built javascript grammar successfully
...

=== Verification ===
✓ python.so (2,456,789 bytes)
✓ javascript.so (1,234,567 bytes)
✓ typescript.so (1,345,678 bytes)
✓ html.so (567,890 bytes)
✓ json.so (123,456 bytes)
✓ yaml.so (234,567 bytes)

✓ All grammars built successfully!

Grammar files are in: ...\build
You can now use UniversalParser!
```

**Build Time:** 3-5 minutes depending on your system

---

### Step 3: Verify Installation

Run the test suite:
```bash
python test_files/test_universal_parser.py
```

**Expected Output:**
```
=== TREE-SITTER UNIVERSAL PARSER TEST SUITE ===

TEST 1: Tree-sitter Installation Check
✓ tree-sitter is installed

TEST 2: Parser Initialization
✓ Parser initialized successfully
  Available languages: ['python', 'javascript', 'typescript', 'html', 'json', 'yaml']

TEST 3: Python Parsing
✓ Parsed Python successfully
  Root type: module
  Children: 2
  Functions found: 2
    - calculate_total at line 2
    - checkout at line 13
  Classes found: 1
    - ShoppingCart at line 7

TEST 4: JavaScript Parsing
✓ Parsed JavaScript successfully
...

=== TEST SUMMARY ===
✓ PASS: test_tree_sitter_available
✓ PASS: test_parser_initialization
✓ PASS: test_python_parsing
✓ PASS: test_javascript_parsing
✓ PASS: test_typescript_parsing
✓ PASS: test_error_resilience
✓ PASS: test_adapter_conversion
✓ PASS: test_universal_ast_parser
✓ PASS: test_complex_constructs

Total: 9/9 tests passed

🎉 All tests passed!
```

---

### Step 4: Run Demo

Optional - see the parser in action:
```bash
python demo_universal_parser.py
```

This demonstrates:
- Python security analysis
- JavaScript modern features
- Scope awareness
- Error resilience

---

## Troubleshooting

### Issue 1: "tree-sitter not installed"

**Symptom:**
```
ModuleNotFoundError: No module named 'tree_sitter'
```

**Solution:**
```bash
pip install tree-sitter
```

If using a virtual environment, make sure it's activated:
```bash
# Windows
.venv\Scripts\activate

# Linux/Mac
source .venv/bin/activate
```

---

### Issue 2: "C compiler not found" (Windows)

**Symptom:**
```
error: Microsoft Visual C++ 14.0 or greater is required
```

**Solution 1: Visual Studio Build Tools (Recommended)**
1. Download: https://visualstudio.microsoft.com/downloads/
2. Install "Desktop development with C++"
3. Restart terminal
4. Run `setup_grammars.py` again

**Solution 2: MinGW**
1. Download: https://www.mingw-w64.org/downloads/
2. Install and add to PATH
3. Run `setup_grammars.py` again

---

### Issue 3: "Git not found"

**Symptom:**
```
✗ git not found
```

**Solution:**
1. Download Git: https://git-scm.com/downloads
2. Install (use default options)
3. Restart terminal
4. Verify: `git --version`
5. Run `setup_grammars.py` again

---

### Issue 4: "Failed to build [language] grammar"

**Symptom:**
```
✗ Failed to build python: [error message]
```

**Solutions:**

**A) Check repository was cloned:**
```bash
ls tree-sitter-repos/tree-sitter-python
```
If empty, delete and re-run:
```bash
rm -rf tree-sitter-repos
python setup_grammars.py
```

**B) Verify C compiler:**
```bash
# Windows
cl.exe

# Linux/Mac
gcc --version
```

**C) Try manual build:**
```python
from tree_sitter import Language

Language.build_library(
    'build/python.so',
    ['tree-sitter-repos/tree-sitter-python']
)
```

---

### Issue 5: Grammar files not found

**Symptom:**
```
WARNING: Grammar file not found: build/python.so
```

**Solution:**
Check if `build/` directory exists:
```bash
ls build/
```

If empty or missing, run:
```bash
python setup_grammars.py
```

Make sure script completes without errors.

---

### Issue 6: Permission errors (Linux/Mac)

**Symptom:**
```
Permission denied
```

**Solution:**
```bash
# Don't use sudo! Instead:
pip install --user tree-sitter

# Or use virtual environment:
python -m venv venv
source venv/bin/activate
pip install tree-sitter
```

---

## Post-Installation

### Verify Directory Structure

After successful installation, you should have:

```
vulcan-backend/
├── build/                    # ← Grammar files
│   ├── python.so
│   ├── javascript.so
│   ├── typescript.so
│   ├── html.so
│   ├── json.so
│   └── yaml.so
│
├── tree-sitter-repos/        # ← Cloned repositories (can delete after build)
│   ├── tree-sitter-python/
│   ├── tree-sitter-javascript/
│   └── ...
│
└── app/domain/analysis/
    ├── universal_parser.py
    └── parser_adapter.py
```

### Optional: Clean Up

After successful build, you can delete the repositories to save space:
```bash
rm -rf tree-sitter-repos
```

The `build/` directory contains everything needed.

---

## Usage After Installation

### In Your Code

```python
# Import the new parser
from app.domain.analysis.parser_adapter import UniversalASTParser

# Use exactly like the old parser
parser = UniversalASTParser(language="javascript")
graph = parser.parse(code, "app.js")

# That's it!
```

### Update semantic_graph_builder.py

```python
# Change this line:
from app.domain.analysis.ast_parser_enhanced import ASTParser

# To this:
from app.domain.analysis.parser_adapter import UniversalASTParser as ASTParser

# Everything else stays the same!
```

---

## System Requirements

### Minimum
- Python 3.8+
- 100 MB disk space
- 2 GB RAM
- C compiler (gcc, clang, or MSVC)

### Recommended
- Python 3.10+
- 500 MB disk space (for repos during build)
- 4 GB RAM
- Multi-core CPU (faster compilation)

---

## Build Time Estimates

| System | Time |
|--------|------|
| Modern desktop (Windows) | 2-3 minutes |
| Modern laptop (Mac M1/M2) | 1-2 minutes |
| Linux server | 2-4 minutes |
| Older hardware | 5-10 minutes |

---

## FAQ

**Q: Do I need to install tree-sitter for each project?**  
A: No, install once per Python environment.

**Q: Can I move the build/ directory?**  
A: Yes, but update `grammar_path` in UniversalParser initialization.

**Q: Do I need internet after setup?**  
A: No, all grammars are local after build.

**Q: Can I use Docker?**  
A: Yes! Include `setup_grammars.py` in your Dockerfile:
```dockerfile
RUN pip install tree-sitter
RUN python setup_grammars.py
```

**Q: What if I only need JavaScript?**  
A: Setup builds all languages. You can delete unused `.so` files from `build/`.

**Q: How much space does it use?**  
A: ~50 MB for grammars, ~200 MB for repos (can delete after build).

---

## Next Steps

1. ✅ Installation complete
2. Run your first parse: `python demo_universal_parser.py`
3. Update your code to use the new parser
4. Enjoy accurate, fast parsing! 🚀

---

## Getting Help

If you encounter issues:

1. Check this troubleshooting section
2. Run tests: `python test_files/test_universal_parser.py`
3. Check setup output: `python setup_grammars.py`
4. See full docs: `Document-MarkDowns/TREE_SITTER_UNIVERSAL_PARSER.md`

---

## Installation Checklist

- [ ] Python 3.8+ installed
- [ ] Git installed
- [ ] C compiler installed
- [ ] `pip install tree-sitter` completed
- [ ] `python setup_grammars.py` completed successfully
- [ ] `build/` directory contains `.so` files
- [ ] Tests pass: `python test_files/test_universal_parser.py`
- [ ] Demo runs: `python demo_universal_parser.py`

**All checked?** You're ready to use the Universal Parser! 🎉
