# Vulcan Backend API Documentation

**Base URL**: `http://localhost:8000`  
**API Version**: `v1`  
**API Base Path**: `/api/v1`

---

## 📋 Table of Contents

1. [Quick Start](#quick-start)
2. [Authentication](#authentication)
3. [Analysis (Core Feature)](#analysis-core-feature)
4. [Scan (Production Detection)](#scan-production-detection)
5. [Repositories](#repositories)
6. [Scans Management](#scans-management)
7. [Graphs](#graphs)
8. [Patches](#patches)
9. [Reports](#reports)
10. [Dashboard](#dashboard)
11. [Notifications](#notifications)
12. [Error Handling](#error-handling)

---

## 🚀 Quick Start

### 1. Start the Backend Server

```bash
# Navigate to backend directory
cd c:\Users\huzai\Desktop\fyp\Vulcan\vulcan-backend

# Install dependencies
pip install -r requirements.txt

# Run the server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 2. Test Health Endpoint

```bash
curl http://localhost:8000/health
```

**Response:**
```json
{
  "status": "ok"
}
```

### 3. Access Interactive API Docs

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

---

## 🔐 Authentication

All endpoints (except `/auth/*` and `/health`) require authentication via JWT token in the `Authorization` header:

```
Authorization: Bearer <access_token>
```

### Register New User

**Endpoint:** `POST /api/v1/auth/register`

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "secure_password123",
  "full_name": "John Doe"
}
```

**Response:** `201 Created`
```json
{
  "id": 1,
  "email": "user@example.com",
  "full_name": "John Doe",
  "role": "user",
  "is_active": true,
  "is_superuser": false,
  "created_at": "2025-11-30T10:00:00Z"
}
```

---

### Login

**Endpoint:** `POST /api/v1/auth/login`

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "secure_password123"
}
```

**Response:** `200 OK`
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

**Frontend Usage:**
```javascript
// Store token
localStorage.setItem('access_token', response.access_token);

// Use in subsequent requests
const headers = {
  'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
  'Content-Type': 'application/json'
};
```

---

### Get Current User

**Endpoint:** `GET /api/v1/auth/me`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "id": 1,
  "email": "user@example.com",
  "full_name": "John Doe",
  "role": "user",
  "is_active": true
}
```

---

### Refresh Token

**Endpoint:** `POST /api/v1/auth/refresh`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

---

### Logout

**Endpoint:** `POST /api/v1/auth/logout`

**Response:** `200 OK`
```json
{
  "ok": true
}
```

---

## 🔍 Analysis (Core Feature)

### Analyze Code for Vulnerabilities

**Endpoint:** `POST /api/v1/analysis/analyze`

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "code": "def get_user(user_id):\n    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n    cursor.execute(query)\n    return cursor.fetchone()",
  "language": "python",
  "filename": "app.py"
}
```

**Request Fields:**
- `code` (string, required): Source code to analyze
- `language` (string, optional): `"python"`, `"javascript"`, or `"typescript"` (default: `"python"`)
- `filename` (string, optional): Filename for context (default: `"source.py"`)

**Response:** `200 OK`
```json
{
  "graph": {
    "nodes": [...],
    "edges": [...]
  },
  "vulnerabilities": [
    {
      "source": {
        "id": "node_1",
        "name": "user_id",
        "file": "app.py",
        "line": 1
      },
      "sink": {
        "id": "node_5",
        "name": "execute",
        "file": "app.py",
        "line": 3
      },
      "severity": "critical",
      "flow_path": [
        {"id": "node_1", "name": "user_id", "line": 1},
        {"id": "node_3", "name": "f-string", "line": 2},
        {"id": "node_5", "name": "execute", "line": 3}
      ],
      "code_snippet": "query = f\"SELECT * FROM users WHERE id = {user_id}\"\ncursor.execute(query)",
      "explanation": "SQL Injection vulnerability: User input flows directly to SQL execution via f-string interpolation without sanitization.",
      "recommended_fix": "Use parameterized queries: cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))",
      "patch": "def get_user(user_id):\n    query = \"SELECT * FROM users WHERE id = ?\"\n    cursor.execute(query, (user_id,))\n    return cursor.fetchone()"
    }
  ]
}
```

**Frontend Example:**
```javascript
const analyzeCode = async (code, language = 'python', filename = 'app.py') => {
  const response = await fetch('http://localhost:8000/api/v1/analysis/analyze', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ code, language, filename })
  });
  
  const result = await response.json();
  return result.vulnerabilities;
};
```

---

### Build Semantic Graph Only

**Endpoint:** `POST /api/v1/analysis/graph`

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "code": "def hello():\n    print('Hello')",
  "language": "python",
  "filename": "app.py"
}
```

**Response:** `200 OK`
```json
{
  "nodes": [
    {
      "id": "node_1",
      "type": "FunctionDef",
      "name": "hello",
      "file": "app.py",
      "line": 1,
      "properties": {}
    }
  ],
  "edges": [
    {
      "source": "node_1",
      "target": "node_2",
      "type": "CFG_FLOW"
    }
  ]
}
```

**Use Case:** Visualization, debugging, understanding code structure without vulnerability detection.

---

### List Recent Findings

**Endpoint:** `GET /api/v1/analysis/findings`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "findings": [],
  "message": "No stored findings yet. Use POST /analysis/analyze to analyze code."
}
```

---

## 🛡️ Scan (Production Detection)

### Scan Code with Enhanced Detection

**Endpoint:** `POST /api/v1/scan`

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "filename": "vulnerable_app.py",
  "code": "def query_user(user_id):\n    query = f'SELECT * FROM users WHERE id={user_id}'\n    cursor.execute(query)",
  "language": "python",
  "enable_llm": true
}
```

**Request Fields:**
- `filename` (string, required): Name of the file being scanned
- `code` (string, required): Source code to scan
- `language` (string, optional): Programming language (default: `"python"`)
- `enable_llm` (boolean, optional): Enable LLM classification (default: `true`)

**Response:** `200 OK`
```json
{
  "success": true,
  "filename": "vulnerable_app.py",
  "language": "python",
  "analysis_time_seconds": 2.47,
  "graph_nodes": 25,
  "graph_edges": 42,
  "rules_executed": 125,
  "slices_found": 3,
  "vulnerabilities_found": 2,
  "vulnerabilities": [
    {
      "id": "vuln_1",
      "type": "SQL_INJECTION_FSTRING",
      "severity": "critical",
      "confidence": 0.95,
      "owasp": "A03",
      "cwe": "CWE-89",
      "location": {
        "file": "vulnerable_app.py",
        "line": 2,
        "column": 12
      },
      "evidence": {
        "source": "user_id",
        "sink": "cursor.execute",
        "data_flow": ["user_id", "f-string", "execute"]
      },
      "analysis": {
        "llm_classification": "VULNERABLE",
        "explanation": "User input flows to SQL execution via f-string without sanitization",
        "remediation": "Use parameterized queries with placeholders",
        "patch": "cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))"
      }
    }
  ],
  "warnings": [],
  "errors": []
}
```

**Frontend Example:**
```javascript
const scanCode = async (filename, code, enableLLM = true) => {
  const response = await fetch('http://localhost:8000/api/v1/scan', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ 
      filename, 
      code, 
      language: 'python',
      enable_llm: enableLLM
    })
  });
  
  return await response.json();
};
```

---

### Demo Scan (Pre-loaded Vulnerable Code)

**Endpoint:** `POST /api/v1/scan/demo`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request Body:** None (uses pre-loaded demo code)

**Response:** Same as main `/scan` endpoint

**Use Case:** Quick testing without providing code.

---

### Scan Service Health Check

**Endpoint:** `GET /api/v1/scan/health`

**Response:** `200 OK`
```json
{
  "status": "healthy",
  "query_store": {
    "total_rules": 125,
    "by_severity": {
      "critical": 45,
      "high": 38,
      "medium": 32,
      "low": 10
    },
    "by_owasp": {
      "A01": 8,
      "A02": 15,
      "A03": 31,
      "A04": 6,
      "A05": 7,
      "A07": 4,
      "A08": 8,
      "A09": 2,
      "A10": 2
    }
  },
  "llm_enabled": true
}
```

---

## 📦 Repositories

### List All Repositories

**Endpoint:** `GET /api/v1/repositories/`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
[
  {
    "id": 1,
    "name": "frontend-app",
    "provider": "github",
    "url": "https://github.com/user/frontend-app",
    "status": "ACTIVE",
    "default_branch": "main",
    "created_at": "2025-11-30T10:00:00Z"
  }
]
```

---

### Create Repository

**Endpoint:** `POST /api/v1/repositories/`

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "name": "backend-api",
  "provider": "github",
  "url": "https://github.com/user/backend-api",
  "token": "ghp_xxxxxxxxxxxxx",
  "status": "ACTIVE"
}
```

**Response:** `201 Created`
```json
{
  "id": 2,
  "name": "backend-api",
  "provider": "github",
  "url": "https://github.com/user/backend-api",
  "status": "ACTIVE",
  "default_branch": "main",
  "created_at": "2025-11-30T12:00:00Z"
}
```

---

### Get Repository

**Endpoint:** `GET /api/v1/repositories/{repo_id}`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "id": 1,
  "name": "frontend-app",
  "provider": "github",
  "url": "https://github.com/user/frontend-app",
  "status": "ACTIVE",
  "default_branch": "main",
  "created_at": "2025-11-30T10:00:00Z"
}
```

---

### Delete Repository

**Endpoint:** `DELETE /api/v1/repositories/{repo_id}`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "ok": true
}
```

---

### Get Repository Branches

**Endpoint:** `GET /api/v1/repositories/{repo_id}/branches`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "branches": ["main", "develop", "feature/new-auth"]
}
```

---

### Upload Repository Archive

**Endpoint:** `POST /api/v1/repositories/{repo_id}/upload`

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: multipart/form-data
```

**Request Body:** (FormData)
- `file`: Archive file (.zip, .tar.gz) - Max 50MB

**Response:** `200 OK`
```json
{
  "filename": "backend-api.zip",
  "size": 12345678,
  "status": "RECEIVED"
}
```

**Frontend Example:**
```javascript
const uploadRepository = async (repoId, file) => {
  const formData = new FormData();
  formData.append('file', file);
  
  const response = await fetch(`http://localhost:8000/api/v1/repositories/${repoId}/upload`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${localStorage.getItem('access_token')}`
    },
    body: formData
  });
  
  return await response.json();
};
```

---

## 🔬 Scans Management

### Start New Scan (Dual Mode: Direct Code OR Repository)

**Endpoint:** `POST /api/v1/scans/start`

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: application/json
```

#### Mode 1: Direct Code Scan

**Request Body:**
```json
{
  "code": "def get_user(user_id):\n    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n    cursor.execute(query)\n    return cursor.fetchone()",
  "language": "python",
  "filename": "app.py",
  "scan_mode": "DEEP"
}
```

**Request Fields (Direct Code):**
- `code` (string, required): Source code to scan (max 400 lines)
- `language` (enum, required): `"python"`, `"javascript"`, `"typescript"`, `"java"`, `"c"`, `"cpp"`, `"go"`, `"php"`
- `filename` (string, optional): Filename for context (e.g., `"app.py"`)
- `scan_mode` (enum, optional): `"QUICK"`, `"DEEP"`, `"FULL"` (default: `"DEEP"`)

#### Mode 2: Repository Scan

**Request Body:**
```json
{
  "repo_id": 1,
  "branch": "main",
  "scan_mode": "DEEP"
}
```

**Request Fields (Repository):**
- `repo_id` (integer, required): Repository ID from database
- `branch` (string, optional): Git branch to scan (default: `"main"`)
- `scan_mode` (enum, optional): `"QUICK"`, `"DEEP"`, `"FULL"` (default: `"DEEP"`)

**Response:** `202 Accepted`
```json
{
  "scan_id": "scan-a1b2c3d4e5f6",
  "status": "PENDING",
  "message": "Scan initiated successfully",
  "input_type": "DIRECT_CODE",
  "created_at": "2025-11-30T12:00:00.000Z"
}
```

**Frontend Example (Direct Code):**
```javascript
const scanDirectCode = async (code, language, filename = 'app.py') => {
  const response = await fetch('http://localhost:8000/api/v1/scans/start', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      code,
      language,
      filename,
      scan_mode: 'DEEP'
    })
  });
  
  const result = await response.json();
  return result.scan_id; // Use for polling
};
```

**Frontend Example (Repository):**
```javascript
const scanRepository = async (repoId, branch = 'main') => {
  const response = await fetch('http://localhost:8000/api/v1/scans/start', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      repo_id: repoId,
      branch,
      scan_mode: 'DEEP'
    })
  });
  
  const result = await response.json();
  return result.scan_id;
};
```

**Validation Errors:**

400-line limit exceeded:
```json
{
  "detail": [
    {
      "type": "value_error",
      "loc": ["body", "code"],
      "msg": "Code exceeds 400-line limit (got 450 lines)"
    }
  ]
}
```

Both code and repo_id provided:
```json
{
  "detail": [
    {
      "type": "value_error",
      "loc": ["body", "repo_id"],
      "msg": "Provide either 'code' or 'repo_id', not both"
    }
  ]
}
```

---

### Get Scan Status

**Endpoint:** `GET /api/v1/scans/{scan_id}/status`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "state": "RUNNING",
  "progress": 45,
  "eta": null,
  "started_at": "2025-11-30T12:00:00.000Z",
  "finished_at": null,
  "current_file": "app.py",
  "files_scanned": 1,
  "total_files": 3
}
```

**Response Fields:**
- `state` (string): `"PENDING"`, `"RUNNING"`, `"COMPLETED"`, `"FAILED"`, `"CANCELLED"`
- `progress` (integer): 0-100 completion percentage
- `started_at` (string): ISO timestamp when scan started
- `finished_at` (string): ISO timestamp when scan completed (null if running)
- `current_file` (string): Currently scanning file (for repo scans)
- `files_scanned` (integer): Number of files completed
- `total_files` (integer): Total files to scan

**Frontend Polling Example:**
```javascript
const pollScanStatus = async (scanId) => {
  const poll = async () => {
    const response = await fetch(
      `http://localhost:8000/api/v1/scans/${scanId}/status`,
      {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token')}`
        }
      }
    );
    
    const status = await response.json();
    
    if (status.state === 'COMPLETED') {
      // Fetch final results
      const summary = await getScanSummary(scanId);
      return summary;
    } else if (status.state === 'FAILED') {
      throw new Error('Scan failed');
    } else if (status.state === 'RUNNING') {
      // Update progress UI
      updateProgressBar(status.progress);
      updateCurrentFile(status.current_file);
      
      // Poll again in 1 second
      await new Promise(resolve => setTimeout(resolve, 1000));
      return poll();
    }
  };
  
  return poll();
};
```

---

### Get Scan Logs

**Endpoint:** `GET /api/v1/scans/{scan_id}/logs`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "logs": [
    "[INFO] Starting direct code scan",
    "[INFO] Language: python",
    "[INFO] Lines of code: 42",
    "[INFO] Analyzing file: app.py",
    "[INFO] Building semantic graph...",
    "[INFO] Graph built: 125 nodes, 203 edges",
    "[INFO] Rules executed: 125",
    "[INFO] Vulnerabilities found: 3",
    "[SUCCESS] Scan completed in 2.47s"
  ]
}
```

**Frontend Example (Real-time Logs):**
```javascript
const streamScanLogs = async (scanId) => {
  let lastLogCount = 0;
  
  const fetchLogs = async () => {
    const response = await fetch(
      `http://localhost:8000/api/v1/scans/${scanId}/logs`,
      {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('access_token')}`
        }
      }
    );
    
    const { logs } = await response.json();
    
    // Only display new logs
    if (logs.length > lastLogCount) {
      const newLogs = logs.slice(lastLogCount);
      newLogs.forEach(log => appendToLogConsole(log));
      lastLogCount = logs.length;
    }
    
    // Continue fetching if scan is still running
    const status = await fetch(
      `http://localhost:8000/api/v1/scans/${scanId}/status`,
      { headers: { 'Authorization': `Bearer ${token}` } }
    ).then(r => r.json());
    
    if (status.state === 'RUNNING' || status.state === 'PENDING') {
      setTimeout(fetchLogs, 500); // Fetch logs every 500ms
    }
  };
  
  fetchLogs();
};
```

---

### Get Scan Summary

**Endpoint:** `GET /api/v1/scans/{scan_id}/summary`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`

**Direct Code Scan Summary:**
```json
{
  "scan_id": "scan-a1b2c3d4e5f6",
  "status": "COMPLETED",
  "input_type": "DIRECT_CODE",
  "total_files": 1,
  "files_scanned": 1,
  "vulnerabilities_found": 3,
  "by_severity": {
    "critical": 2,
    "high": 1,
    "medium": 0,
    "low": 0
  },
  "duration_seconds": 2.47,
  "created_at": "2025-11-30T12:00:00.000Z",
  "completed_at": "2025-11-30T12:00:02.470Z",
  "vulnerabilities": [
    {
      "id": "vuln_1",
      "type": "SQL_INJECTION_FSTRING",
      "severity": "critical",
      "confidence": 0.95,
      "owasp": "A03",
      "cwe": "CWE-89",
      "location": {
        "file": "app.py",
        "line": 2,
        "column": 12
      },
      "evidence": {
        "source": "user_id",
        "sink": "cursor.execute",
        "data_flow": ["user_id", "f-string", "execute"]
      },
      "analysis": {
        "llm_classification": {
          "classification": "VULNERABLE",
          "severity": "critical",
          "confidence": 0.95,
          "explanation": "User input flows directly to SQL execution via f-string without sanitization",
          "remediation": "Use parameterized queries with placeholders"
        },
        "patch": "cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))"
      }
    }
  ]
}
```

**Repository Scan Summary:**
```json
{
  "scan_id": "scan-x7y8z9a0b1c2",
  "status": "COMPLETED",
  "input_type": "REPOSITORY",
  "total_files": 42,
  "files_scanned": 42,
  "vulnerabilities_found": 15,
  "by_severity": {
    "critical": 3,
    "high": 5,
    "medium": 6,
    "low": 1
  },
  "duration_seconds": 87.93,
  "created_at": "2025-11-30T12:00:00.000Z",
  "completed_at": "2025-11-30T12:01:27.930Z",
  "vulnerabilities": [
    {
      "id": "vuln_1",
      "file": "app/routes/auth.py",
      "type": "SQL_INJECTION_CONCAT",
      "severity": "critical",
      "confidence": 0.98,
      "location": { "line": 42 },
      "analysis": {
        "llm_classification": {
          "classification": "VULNERABLE",
          "explanation": "...",
          "remediation": "..."
        }
      }
    }
  ]
}
```

---

### Cancel Scan

**Endpoint:** `POST /api/v1/scans/{scan_id}/cancel`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "scan_id": "scan-a1b2c3d4e5f6",
  "status": "CANCELLED"
}
```

---

## 📊 Graphs

### Get File Graph

**Endpoint:** `GET /api/v1/graphs/{scan_id}/file/{file_id}`

**Query Parameters:**
- `type` (string, optional): `"AST"`, `"CFG"`, or `"DFG"` (default: `"AST"`)

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "nodes": [...],
  "edges": [...],
  "type": "AST"
}
```

---

### Get Node Details

**Endpoint:** `GET /api/v1/graphs/{scan_id}/nodes/{node_id}`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "node_id": "node_123",
  "details": {
    "severity": "LOW"
  },
  "insight": "Likely benign"
}
```

---

### Get Path Details

**Endpoint:** `GET /api/v1/graphs/{scan_id}/paths/{path_id}`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "path_id": "path_456",
  "steps": ["source", "sanitize", "sink"],
  "risk": "LOW"
}
```

---

## 🩹 Patches

### List Patchable Vulnerabilities

**Endpoint:** `GET /api/v1/patches/{scan_id}/vulnerabilities`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
[
  {
    "vulnerability_id": "vuln_1",
    "type": "SQL_INJECTION",
    "severity": "critical",
    "patchable": true
  }
]
```

---

### Generate Patch

**Endpoint:** `POST /api/v1/patches/generate`

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "vulnerability_id": "vuln_1",
  "options": {
    "style": "minimal",
    "include_tests": false
  }
}
```

**Response:** `201 Created`
```json
{
  "patch_id": 1,
  "vulnerability_id": "vuln_1",
  "patch_code": "cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))",
  "status": "GENERATED"
}
```

---

### Get Patch

**Endpoint:** `GET /api/v1/patches/{patch_id}`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "patch_id": 1,
  "vulnerability_id": "vuln_1",
  "patch_code": "...",
  "status": "GENERATED",
  "created_at": "2025-11-30T12:00:00Z"
}
```

---

### Apply Patch

**Endpoint:** `POST /api/v1/patches/{patch_id}/apply`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "patch_id": 1,
  "status": "APPLIED",
  "applied_at": "2025-11-30T12:05:00Z"
}
```

---

### Export Patch

**Endpoint:** `POST /api/v1/patches/{patch_id}/export`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "patch_id": 1,
  "format": "diff",
  "content": "--- a/app.py\n+++ b/app.py\n..."
}
```

---

### Regenerate Patch

**Endpoint:** `POST /api/v1/patches/{patch_id}/regenerate`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "patch_id": 1,
  "status": "REGENERATED",
  "new_patch_code": "..."
}
```

---

## 📈 Reports

### List Reports

**Endpoint:** `GET /api/v1/reports`

**Query Parameters:**
- `repo_id` (integer, optional): Filter by repository
- `date_from` (string, optional): Start date (ISO 8601)
- `date_to` (string, optional): End date (ISO 8601)
- `tag` (string, optional): Filter by tag

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
[
  {
    "report_id": 1,
    "repo_id": 1,
    "scan_id": "scan_abc123",
    "created_at": "2025-11-30T12:00:00Z",
    "vulnerabilities_count": 15
  }
]
```

---

### Get Report

**Endpoint:** `GET /api/v1/reports/{report_id}`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "report_id": 1,
  "repo_id": 1,
  "scan_id": "scan_abc123",
  "summary": {
    "total_vulnerabilities": 15,
    "by_severity": {
      "critical": 2,
      "high": 5,
      "medium": 6,
      "low": 2
    }
  },
  "vulnerabilities": [...]
}
```

---

### Export Report

**Endpoint:** `GET /api/v1/reports/{report_id}/export`

**Query Parameters:**
- `format` (string, optional): `"json"`, `"pdf"`, or `"csv"` (default: `"json"`)

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK` (Returns file download)

---

### Compare Reports

**Endpoint:** `POST /api/v1/reports/compare`

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "report_id_1": 1,
  "report_id_2": 2
}
```

**Response:** `200 OK`
```json
{
  "new_vulnerabilities": 3,
  "fixed_vulnerabilities": 5,
  "unchanged_vulnerabilities": 10
}
```

---

## 📊 Dashboard

### Get Summary Statistics

**Endpoint:** `GET /api/v1/dashboard/summary`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "totals": {
    "repos": 5,
    "scans": 42,
    "vulnerabilities": 213
  },
  "severity": {
    "CRITICAL": 7,
    "HIGH": 23,
    "MEDIUM": 91,
    "LOW": 92
  },
  "ai": {
    "patch_success_rate": 0.71,
    "avg_confidence": 0.83
  },
  "trend": [
    {"date": "2025-11-01", "scans": 2},
    {"date": "2025-11-02", "scans": 3},
    {"date": "2025-11-03", "scans": 4}
  ]
}
```

---

### Get Recent Scans

**Endpoint:** `GET /api/v1/dashboard/recent-scans`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
[
  {
    "scan_id": "abc123",
    "repo": "frontend-app",
    "status": "COMPLETED",
    "created_at": "2025-11-02T11:00:00Z"
  },
  {
    "scan_id": "def456",
    "repo": "api-server",
    "status": "RUNNING",
    "created_at": "2025-11-03T10:00:00Z"
  }
]
```

---

### Get Dashboard Notifications

**Endpoint:** `GET /api/v1/dashboard/notifications`

**Query Parameters:**
- `page` (integer, optional): Page number (default: 1)
- `size` (integer, optional): Page size (default: 10)

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "items": [...],
  "total": 25,
  "page": 1,
  "size": 10
}
```

---

## 🔔 Notifications

### List Notifications

**Endpoint:** `GET /api/v1/notifications`

**Query Parameters:**
- `page` (integer, optional): Page number (default: 1)
- `size` (integer, optional): Page size (default: 10)

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** `200 OK`
```json
{
  "items": [
    {
      "id": 1,
      "message": "Scan completed for frontend-app",
      "type": "INFO",
      "read": false,
      "created_at": "2025-11-30T12:00:00Z"
    }
  ],
  "total": 25,
  "page": 1,
  "size": 10
}
```

---

## ⚠️ Error Handling

### Standard Error Response

```json
{
  "detail": "Error message here"
}
```

### HTTP Status Codes

| Code | Meaning | Description |
|------|---------|-------------|
| 200 | OK | Request successful |
| 201 | Created | Resource created |
| 202 | Accepted | Request accepted (async) |
| 400 | Bad Request | Invalid request body/parameters |
| 401 | Unauthorized | Missing or invalid token |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 413 | Payload Too Large | File upload exceeds limit |
| 422 | Unprocessable Entity | Validation error |
| 500 | Internal Server Error | Server error |
| 503 | Service Unavailable | Service temporarily unavailable |

### Frontend Error Handling Example

```javascript
const handleAPIError = async (response) => {
  if (!response.ok) {
    const error = await response.json();
    
    switch (response.status) {
      case 401:
        // Redirect to login
        window.location.href = '/login';
        break;
      case 422:
        // Validation error
        alert(`Validation Error: ${error.detail}`);
        break;
      default:
        alert(`Error: ${error.detail}`);
    }
    
    throw new Error(error.detail);
  }
  
  return response.json();
};
```

---

## 🎯 Frontend Integration Examples

### React Example

```javascript
import { useState, useEffect } from 'react';

const API_BASE = 'http://localhost:8000/api/v1';

// Hook for authentication
const useAuth = () => {
  const [token, setToken] = useState(localStorage.getItem('access_token'));
  
  const login = async (email, password) => {
    const response = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    
    const data = await response.json();
    localStorage.setItem('access_token', data.access_token);
    setToken(data.access_token);
  };
  
  const logout = () => {
    localStorage.removeItem('access_token');
    setToken(null);
  };
  
  return { token, login, logout };
};

// Component for code scanning
const CodeScanner = () => {
  const { token } = useAuth();
  const [code, setCode] = useState('');
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(false);
  
  const scanCode = async () => {
    setLoading(true);
    
    const response = await fetch(`${API_BASE}/scan`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        filename: 'code.py',
        code,
        language: 'python',
        enable_llm: true
      })
    });
    
    const result = await response.json();
    setVulnerabilities(result.vulnerabilities);
    setLoading(false);
  };
  
  return (
    <div>
      <textarea value={code} onChange={(e) => setCode(e.target.value)} />
      <button onClick={scanCode} disabled={loading}>
        {loading ? 'Scanning...' : 'Scan Code'}
      </button>
      
      <div>
        {vulnerabilities.map((vuln, i) => (
          <div key={i} className={`severity-${vuln.severity}`}>
            <h3>{vuln.type}</h3>
            <p>{vuln.analysis.explanation}</p>
            <pre>{vuln.analysis.patch}</pre>
          </div>
        ))}
      </div>
    </div>
  );
};
```

---

## 🔧 Configuration

### Environment Variables (.env)

Create a `.env` file in the backend root:

```env
# Environment
ENV=dev

# API Configuration
API_V1_STR=/api/v1
PROJECT_NAME=VULCAN API

# CORS (add your frontend URL)
BACKEND_CORS_ORIGINS=http://localhost:3000,http://localhost:5173

# Database
DATABASE_URL=sqlite+aiosqlite:///./vulcan.db

# JWT Configuration
JWT_SECRET=your-super-secret-key-change-this-in-production
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
REFRESH_TOKEN_EXPIRE_MINUTES=43200

# Default Admin Credentials
DEFAULT_ADMIN_EMAIL=admin@vulcan.ai
DEFAULT_ADMIN_PASSWORD=admin123!

# LLM Configuration (Optional)
GITHUB_TOKEN=your_github_token_for_llm_api
```

---

## 🚀 Production Deployment

### Using Docker

```bash
# Build image
docker build -t vulcan-backend .

# Run container
docker run -p 8000:8000 \
  -e DATABASE_URL=postgresql://user:pass@db:5432/vulcan \
  -e JWT_SECRET=production-secret \
  vulcan-backend
```

### Using Gunicorn

```bash
gunicorn app.main:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000
```

---

## 📝 Notes

1. **Default Admin User**: On first startup, a default admin user is created:
   - Email: `admin@vulcan.ai`
   - Password: `admin123!`
   - **Change these credentials immediately in production!**

2. **CORS Configuration**: Update `BACKEND_CORS_ORIGINS` in `.env` to match your frontend URL.

3. **LLM Classification**: Requires GitHub token for LLM API access. Set `GITHUB_TOKEN` environment variable.

4. **Rate Limiting**: Not implemented yet. Consider adding in production.

5. **File Upload Limits**: Maximum 50MB for repository archives.

6. **Database**: Uses SQLite by default. For production, use PostgreSQL:
   ```env
   DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/vulcan
   ```

---

## 🆘 Support

For issues or questions:
- Check `/docs` for interactive API documentation
- Review logs in terminal running the server
- Check database state: `sqlite3 vulcan.db`

---

**Last Updated:** November 30, 2025  
**API Version:** 1.0.0
