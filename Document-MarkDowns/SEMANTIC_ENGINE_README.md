# Vulcan Backend - AI-Powered Unified CPG Security Scanner

Production-grade vulnerability detection engine using **Unified Code Property Graph (CPG)** + **Static Query Rules** + **LLM Classification** (Meta-Llama-3.1-405B-Instruct).

## 🚀 Key Features

✅ **Unified Code Property Graph**: AST + CFG + DFG in one graph structure  
✅ **Static Query Rules**: 15 OWASP Top 10 security patterns (Json-based)  
✅ **AI-Powered Classification**: LLM validates findings & reduces false positives  
✅ **Multi-Language Support**: Python (with JS/TS foundation)  
✅ **Production Ready**: Guardrails, timeouts, cycle detection, error handling  
✅ **REST API**: FastAPI endpoints for code scanning  
✅ **Custom System Prompt**: Vulcan-LLM specialized for security analysis  

---

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

Required packages:
- `fastapi>=0.110` - Web framework
- `pyyaml>=6.0` - Query rule loading
- `openai>=1.0` - For LLM classification (GitHub Models compatible)
- `python-dotenv` - Environment configuration

### 2. Configure LLM

Set environment variables in `.env`:

```bash
# LLM Configuration (GitHub Models API)
LLM_PROVIDER=github
LLM_API_KEY=your_github_token_here
LLM_MODEL_CLASSIFIER=Meta-Llama-3.1-405B-Instruct
LLM_BASE_URL=https://models.inference.ai.azure.com
ENABLE_LLM=true
```

**System Prompt**: Automatically loaded from `app/LLM-prompts/detect-system-prompt.txt`

The Vulcan-LLM prompt instructs the AI to:
- Analyze code slices from taint tracking
- Classify OWASP Top 10 vulnerabilities
- Provide detailed explanations & remediation

**Note**: LLM is enabled by default for accurate detection. See [LLM_INTEGRATION_GUIDE.md](LLM_INTEGRATION_GUIDE.md) for details.

### 3. Run Tests

```bash
python test_semantic_pipeline.py
```

Expected output:
```
✓ PASS - Query Store
✓ PASS - SQL Injection Detection
✓ PASS - Pipeline - Safe Code
Total: 3/4 tests passed
```

### 4. Start Server

```bash
uvicorn app.main:app --reload --port 8000
```

Server runs at: `http://localhost:8000`

---

## API Endpoints

### POST /api/v1/scan
Scan code for vulnerabilities with full semantic analysis.

**Request**:
```json
{
  "filename": "app.py",
  "code": "def query_user(user_id):\n    query = f'SELECT * FROM users WHERE id={user_id}'\n    cursor.execute(query)",
  "language": "python",
  "enable_llm": true
}
```

**Response**:
```json
{
  "success": true,
  "vulnerabilities_found": 1,
  "vulnerabilities": [
    {
      "id": "SQL_INJECTION_node_2_node_8",
      "type": "SQL Injection",
      "severity": "critical",
      "confidence": 0.85,
      "owasp": "A03",
      "cwe": "CWE-89",
      "location": {
        "file": "app.py",
        "start_line": 2,
        "end_line": 3
      },
      "evidence": {
        "source": "user_id",
        "sink": "execute",
        "code_snippet": ">>> 2 | query = f'SELECT * FROM users WHERE id={user_id}'\n>>> 3 | cursor.execute(query)"
      },
      "analysis": {
        "llm_classification": {
          "classification": "VULNERABLE",
          "explanation": "User input flows directly into SQL query without parameterization",
          "remediation": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))"
        }
      }
    }
  ]
}
```

### POST /api/v1/scan/demo
Quick demo endpoint with pre-loaded vulnerable code.

### GET /api/v1/scan/health
Check service health and query statistics.

---

## Query Rules

Located in `queries/queries.yaml` - 15 security patterns covering OWASP Top 10:

| Rule ID | Name | OWASP | Severity | Detection Method |
|---------|------|-------|----------|-----------------|
| SQL_INJECTION | SQL Injection | A03 | Critical | Source→Sink DFG/Taint Flow |
| COMMAND_INJECTION | OS Command Injection | A03 | Critical | Source→Sink Flow |
| XSS | Cross-Site Scripting | A03 | High | Source→Sink Flow |
| PATH_TRAVERSAL | Path Traversal | A01 | High | Source→Sink Flow |
| SSRF | Server-Side Request Forgery | A10 | High | Source→Sink Flow |
| BROKEN_ACCESS_CONTROL | Broken Access Control | A01 | High | Missing Auth Guards |
| INSECURE_DESERIALIZATION | Insecure Deserialization | A08 | Critical | Unsafe pickle/eval |
| WEAK_CRYPTO | Weak Cryptography | A02 | Medium | Algorithm Blacklist |
| HARDCODED_SECRETS | Hardcoded Secrets | A07 | Critical | Regex Patterns |
| DEBUG_MODE_ENABLED | Debug Mode in Production | A05 | Medium | Setting Detection |
| LDAP_INJECTION | LDAP Injection | A03 | High | Source→Sink Flow |
| XML_INJECTION | XML External Entity (XXE) | A05 | High | XMLParser Settings |
| MASS_ASSIGNMENT | Mass Assignment | A01 | Medium | Pattern Detection |
| CORS_MISCONFIGURATION | CORS Misconfiguration | A05 | Medium | Config Detection |
| TIMING_ATTACK | Timing Attack | A04 | Low | Comparison Detection |

### Adding Custom Rules

Edit `queries/queries.yaml`:

```yaml
MY_CUSTOM_RULE:
  name: "Custom Security Check"
  owasp: "A03"
  cwe: "CWE-XXX"
  description: "Detects custom vulnerability pattern"
  severity: high
  sources:
    - user_input_func
    - request.custom_field
  sinks:
    - dangerous_func
    - unsafe_operation
  patterns:
    - "DFG_FLOW"
    - "TAINT_FLOW"
  sanitizers:
    - validation_func
    - escape_func
  confidence: medium
```

Reload: Query store auto-reloads on file change.

---

## Architecture Details

### Components

1. **semantic_engine/query_store/** - YAML query rule management
   - `loader.py` - Load, cache, reload queries
   - Supports filtering by OWASP, CWE, severity

2. **semantic_engine/query_executor/** - Pattern matching engine
   - `executor.py` - Find source→sink paths in CPG
   - BFS path finding with sanitizer detection
   - Code slice extraction with context

3. **semantic_engine/classifier/** - LLM validation layer
   - `llm_service.py` - OpenAI/Anthropic/Groq integration
   - `classifier.py` - Slice classification orchestration
   - Returns: SAFE | VULNERABLE | LIKELY_VULNERABLE | UNKNOWN

4. **semantic_engine/pipeline.py** - End-to-end orchestrator
   - Parse → AST → CFG → DFG → Unified Graph
   - Execute queries → Extract slices → Classify
   - Guardrails: timeouts, node limits, cycle detection

5. **app/api/routes/scan.py** - FastAPI endpoints
   - POST /scan - Full analysis
   - POST /scan/demo - Quick test
   - GET /scan/health - Status check

### Data Flow

```
Code String
    ↓
AST Parser (Python ast module)
    ↓
CFG Builder (control flow)
    ↓
DFG Builder (data flow + variable tracking)
    ↓
Unified CPG (nodes + edges with types)
    ↓
Query Executor (for each rule):
    - Resolve sources (e.g., request.GET)
    - Resolve sinks (e.g., cursor.execute)
    - Find paths (BFS with sanitizer checks)
    - Extract slices (minimal code + context)
    ↓
LLM Classifier (for each slice):
    - Build prompt with code + rule
    - Call GPT-4/Claude
    - Parse JSON response
    - Combine with static analysis
    ↓
Validated Vulnerabilities (sorted by severity)
```

---

## Testing

### Unit Tests

```bash
python test_semantic_pipeline.py
```

Tests:
- [x] Query store loading (15 rules)
- [x] SQL injection detection  
- [x] Safe code (no false positives)
- [x] Full pipeline integration

### Manual Testing

Use the demo endpoint:

```bash
curl -X POST http://localhost:8000/api/v1/scan/demo | jq
```

Or test with custom code:

```bash
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "filename": "test.py",
    "code": "import os; os.system(input(\"cmd: \"))",
    "language": "python",
    "enable_llm": false
  }' | jq
```

---

## Performance & Guardrails

| Guardrail | Default | Purpose |
|-----------|---------|---------|
| Max Graph Nodes | 200,000 | Prevent memory issues on large files |
| Max Path Length | 50 | Avoid infinite loops in path finding |
| Max Paths per Rule | 100 | Limit false positives |
| Query Timeout | 30s | Prevent query executor hangs |
| LLM Timeout | 15s | Prevent LLM API hangs |
| Cycle Detection | Enabled | Detect graph cycles early |

Configure in `PipelineConfig`:

```python
from semantic_engine.pipeline import PipelineConfig, get_pipeline

config = PipelineConfig(
    enable_llm=True,
    max_graph_nodes=100_000,
    max_path_length=30,
    llm_timeout=10
)

pipeline = get_pipeline(config)
```

---

## Extending the System

### Add New Language Support

1. Create parser in `semantic_engine/ast/`
2. Implement `parse()` returning `SemanticGraph`
3. Update `pipeline.py` to route language
4. Add language-specific sources/sinks to `queries.yaml`

### Add New Detection Patterns

1. Edit `queries/queries.yaml`:
   ```yaml
   NEW_RULE:
     name: "Description"
     owasp: "A0X"
     severity: high
     sources: [...]
     sinks: [...]
     patterns: ["DFG_FLOW"]
   ```

2. Query store auto-reloads

3. Test with `POST /scan`

### Integrate Custom LLM

Implement in `semantic_engine/classifier/llm_service.py`:

```python
class LLMService:
    def _call_llm(self, prompt: str) -> str:
        if self.provider == 'my_custom_llm':
            # Your LLM API call here
            return response.text
```

---

## Production Deployment

### Environment Variables

```bash
# Required
DATABASE_URL=postgresql://...
SECRET_KEY=your-secret-key-here

# Optional - LLM
LLM_PROVIDER=openai  # or anthropic, groq
LLM_API_KEY=sk-...
LLM_MODEL_CLASSIFIER=gpt-4

# Optional - Logging
LOG_LEVEL=INFO
```

### Docker Deployment

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

Build & Run:
```bash
docker build -t vulcan-backend .
docker run -p 8000:8000 -e LLM_API_KEY=sk-... vulcan-backend
```

---

## Troubleshooting

### "Graph too large" Error

**Cause**: File exceeds 200k nodes  
**Solution**: Increase `max_graph_nodes` in config

### "LLM timeout" Warning

**Cause**: LLM API slow/unavailable  
**Solution**: System falls back to static analysis. Check API key and network.

### No Vulnerabilities Detected

**Cause**: Sources/sinks don't match query patterns  
**Solution**:
1. Check `queries.yaml` has correct patterns for your code
2. Review graph with `POST /api/v1/analysis` endpoint
3. Add logging: `LOG_LEVEL=DEBUG`

### False Positives

**Cause**: Static pattern matching too broad  
**Solution**:
1. Enable LLM classification (`enable_llm=true`)
2. Add sanitizers to `queries.yaml`
3. Adjust confidence thresholds

---

## Roadmap

- [x] Unified CPG with AST+CFG+DFG
- [x] Static YAML query rules
- [x] LLM classification
- [x] Python support
- [ ] JavaScript/TypeScript support
- [ ] Cross-file taint tracking
- [ ] Continuous monitoring mode
- [ ] GitHub App integration
- [ ] Custom remediation templates
- [ ] Multi-repository scanning

---

## License

MIT License - See LICENSE file

## Contributors

- **Vulcan Security Team** - Initial development
- **Community** - Bug reports, feature requests

## Support

- Documentation: `/docs` (FastAPI auto-docs)
- Issues: GitHub Issues
- Email: security@vulcan.dev

---

**Built with ❤️ for secure code**
