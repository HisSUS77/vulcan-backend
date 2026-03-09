VULCAN Backend (FastAPI)
========================

Quickstart (Windows PowerShell)
--------------------------------

1) Create venv and install dependencies

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -U pip
pip install -r requirements.txt
```

2) Configure environment

Copy `.env` (already included) and adjust as needed:

```
ENV=dev
API_V1_STR=/api/v1
PROJECT_NAME=VULCAN API
BACKEND_CORS_ORIGINS=http://localhost:3000
DATABASE_URL=sqlite+aiosqlite:///./vulcan.db
# DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/vulcan
JWT_SECRET=change-me-super-secret
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
REFRESH_TOKEN_EXPIRE_MINUTES=43200
DEFAULT_ADMIN_EMAIL=admin@vulcan.ai
DEFAULT_ADMIN_PASSWORD=admin123!
```

3) Run the server

```powershell
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000/docs

Default Credentials
-------------------

- Email: `admin@vulcan.ai`
- Password: `admin123!`

API Base Path
-------------

- All routes are under `/api/v1`.
- Health check: `GET /health`

Implemented Modules
-------------------

- Auth: register, login, logout, me, refresh (JWT bearer)
- Dashboard: summary, recent scans, notifications
- Repositories: CRUD, branches, upload (ZIP/TAR up to 200MB)
- Scans: start, status, logs, summary, cancel (mock background)
- Graphs: AST/CFG/DFG mocks
- Patches: list vulns, generate/get/apply/export/regenerate (mocks)
- Reports: list/get/export/compare (mocks)

# vulcan-backend
Ye shall not cheat :(