# VULCAN React Frontend Integration Guide

This guide explains how to connect the VULCAN React frontend to this FastAPI backend. It covers base URLs, authentication flow, common headers, endpoint usage, and example client code.

- API base path: `/api/v1`
- CORS allowed origin (dev): `http://localhost:3000`
- Default admin login: `admin@vulcan.ai` / `admin123!`

## Environment Setup (Frontend)

- Create a frontend env variable pointing at this server:
  - Create React App: add `.env.local`
    ```bash
    REACT_APP_API_BASE_URL=http://127.0.0.1:8000/api/v1
    ```
  - Vite: add `.env.local`
    ```bash
    VITE_API_BASE_URL=http://127.0.0.1:8000/api/v1
    ```
- Ensure the frontend runs at `http://localhost:3000` (CORS allows it by default).

## Auth Model

- JWT Bearer tokens are returned by `POST /auth/login`.
- Include the token on subsequent requests as `Authorization: Bearer <access_token>`.
- Token payload includes `sub` (user id) and `exp`.
- Refresh endpoint exists but is optional; current implementation returns a new token only if the current token is still valid. Prefer re-login on 401 for now.

### Endpoints

- `POST /auth/login` → `{ access_token, token_type, expires_in }`
- `GET /auth/me` → current user profile
- `POST /auth/logout` → `{ ok: true }` (stateless; just drop token client-side)
- `POST /auth/refresh` → `{ access_token, ... }` (optional)

### Sample Login Request

```http
POST /api/v1/auth/login
Content-Type: application/json

{ "email": "admin@vulcan.ai", "password": "admin123!" }
```

### Sample Login Response

```json
{ "access_token": "<jwt>", "token_type": "bearer", "expires_in": 3600 }
```

## API Client (Axios) Example

```ts
// src/api/client.ts
import axios from 'axios';

const baseURL =
  (import.meta as any)?.env?.VITE_API_BASE_URL || process.env.REACT_APP_API_BASE_URL || 'http://127.0.0.1:8000/api/v1';

export const api = axios.create({ baseURL });

// simple token store; replace with your auth state/context
let accessToken: string | null = null;
export const setAccessToken = (t: string | null) => { accessToken = t; };

api.interceptors.request.use((config) => {
  if (accessToken) config.headers.Authorization = `Bearer ${accessToken}`;
  return config;
});

api.interceptors.response.use(
  (res) => res,
  async (err) => {
    if (err?.response?.status === 401) {
      // drop token and redirect to login; refresh is optional for now
      setAccessToken(null);
      // optionally route to /login
    }
    return Promise.reject(err);
  }
);
```

## Auth Hook/Context (Sketch)

```ts
// src/auth/useAuth.ts
import { useState } from 'react';
import { api, setAccessToken } from '../api/client';

export function useAuth() {
  const [user, setUser] = useState<any>(null);

  async function login(email: string, password: string) {
    const { data } = await api.post('/auth/login', { email, password });
    setAccessToken(data.access_token);
    const me = await api.get('/auth/me');
    setUser(me.data);
    return me.data;
  }

  function logout() {
    setAccessToken(null);
    setUser(null);
  }

  return { user, login, logout };
}
```

## Protected Fetch Example

```ts
// repo list
const { data } = await api.get('/repositories');
```

## Feature Endpoints

### Dashboard
- `GET /dashboard/summary` → totals, severity distribution, AI metrics, trend.
- `GET /dashboard/recent-scans` → recent scan entries.
- `GET /notifications?page=1&size=10` → paginated notifications.

### Repositories
- `GET /repositories` → list
- `POST /repositories` → create: `{ name, provider, url?, token?, status? }`
- `GET /repositories/{id}` → details
- `DELETE /repositories/{id}` → delete
- `GET /repositories/{id}/branches` → array of branch names
- `POST /repositories/{id}/upload` (multipart) → accepts `.zip`/`.tar.gz`
  - Max size: ~200MB; on exceed: `413` or `422` with message
  - Example upload:
    ```ts
    const form = new FormData();
    form.append('file', file); // File object from input
    const res = await api.post(`/repositories/${repoId}/upload`, form, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    ```

### Scans
- `POST /scans/start` `{ repo_id, branch, scan_mode }` → `202 { scan_id }`
- `GET /scans/{scan_id}/status` → `{ state, progress, eta, started_at, finished_at }`
- `GET /scans/{scan_id}/logs` → `{ logs: string[] }`
- `GET /scans/{scan_id}/summary` → severity counts + `ai_confidence`
- `POST /scans/{scan_id}/cancel` → `{ state: 'CANCELLED' }`

Polling example:
```ts
const poll = (scanId: string, onTick: (s: any) => void) => {
  const id = setInterval(async () => {
    const { data } = await api.get(`/scans/${scanId}/status`);
    onTick(data);
    if (['COMPLETED','FAILED','CANCELLED'].includes(data.state)) clearInterval(id);
  }, 1000);
  return () => clearInterval(id);
};
```

### Graphs
- `GET /graphs/{scan_id}/file/{file_id}?type=AST|CFG|DFG` → `{ type, nodes, edges, meta }`
- `GET /graphs/{scan_id}/nodes/{node_id}` → node details + AI insight (mock)
- `GET /graphs/{scan_id}/paths/{path_id}` → taint path details (mock)

### Patches
- `GET /patches/{scan_id}/vulnerabilities` → list of patchable vulns
- `POST /patches/generate` `{ vulnerability_id, options? }` → `201 { patch... }`
- `GET /patches/{patch_id}` → patch details
- `POST /patches/{patch_id}/apply` → `{ status: 'APPLIED', branch }`
- `POST /patches/{patch_id}/export` → `{ filename, content }` (unified diff)
- `POST /patches/{patch_id}/regenerate` → `{ patch_id, version }`

### Reports
- `GET /reports?repo_id=&date_from=&date_to=&tag=` → list
- `GET /reports/{id}` → full report
- `GET /reports/{id}/export?format=json|csv|pdf` → export
- `POST /reports/compare` `{ report_id_1, report_id_2 }` → comparison

## Error Handling
- `401 Unauthorized`: token missing/invalid/expired → clear token and route to login.
- `404 Not Found`: entity absent (repo/scan/patch/report).
- `413/422`: upload size/format issues.
- All errors return `{ "detail": "..." }` style messages.

## Quick Frontend Checklist
- [ ] Set `REACT_APP_API_BASE_URL` (or `VITE_API_BASE_URL`).
- [ ] Replace any dummy token with real JWT from `/auth/login`.
- [ ] Add Axios interceptor to attach `Authorization` header.
- [ ] Implement login → store token → call `/auth/me` to hydrate user.
- [ ] Guard protected routes (redirect to login on 401).
- [ ] Wire UI calls to endpoints above (repositories, scans, graphs, patches, reports, notifications).
- [ ] Integrate semantic analysis endpoints for advanced vulnerability detection.

## Advanced Analysis (NEW)

The backend now includes semantic graph-based taint analysis for detecting security vulnerabilities in source code.

### Analyze Code

**POST /api/v1/analysis/analyze**

Analyzes source code for security vulnerabilities using semantic graph analysis (AST + CFG + DFG + taint tracking + LLM reasoning).

```ts
interface AnalyzeRequest {
  code: string;
  language: "python" | "javascript" | "typescript";
  filename?: string;
}

interface AnalyzeResponse {
  graph: {
    nodes: Array<{
      id: string;
      type: string;
      name?: string;
      file: string;
      line: number;
    }>;
    edges: Array<{
      from: string;
      to: string;
      type: string;
    }>;
  };
  vulnerabilities: Array<{
    source: { id: string; name: string; line: number };
    sink: { id: string; name: string; line: number };
    severity: "low" | "medium" | "high" | "critical";
    flow_path: Array<{ id: string; name: string; line: number }>;
    code_snippet: string;
    explanation: string;
    recommended_fix: string;
    patch: string;
  }>;
}
```

Example request:
```ts
const result = await api.post('/analysis/analyze', {
  code: `
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()
  `,
  language: 'python',
  filename: 'user_service.py'
});

// Result contains graph + detected SQL injection vulnerability
console.log(result.data.vulnerabilities[0]);
// {
//   severity: "critical",
//   explanation: "SQL Injection detected...",
//   recommended_fix: "Use parameterized queries...",
//   patch: "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
// }
```

### Build Semantic Graph

**POST /api/v1/analysis/graph**

Builds and returns just the semantic graph without running taint analysis (useful for visualization).

```ts
const graphResult = await api.post('/analysis/graph', {
  code: sourceCode,
  language: 'python',
  filename: 'app.py'
});

// Returns just the graph structure
console.log(graphResult.data.nodes.length);
console.log(graphResult.data.edges.length);
```

### List Findings

**GET /api/v1/analysis/findings**

Lists recent vulnerability findings (currently returns placeholder, can be enhanced to persist findings in DB).

```ts
const findings = await api.get('/analysis/findings');
```

## Notes
- This backend ships with mock engines so all endpoints work out of the box.
- Default DB is SQLite; no frontend change required.
- OAuth routes return `501` placeholders.
- **NEW**: Semantic analysis currently supports Python with plans for JavaScript/TypeScript.
- **NEW**: Detects SQL injection, command injection, XSS, path traversal via taint tracking.
- **NEW**: Provides automated patch suggestions for detected vulnerabilities.