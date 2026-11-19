# SENTINEL-X
## Intelligent Security Monitoring & Threat Detection Platform

**Tagline:** Detect. Analyse. Defend.  
**Version:** 1.1.0  
**Project type:** Individual educational cybersecurity project

SENTINEL-X is an administrator-only defensive security event analysis platform. An authorised administrator signs in, imports structured authentication logs in CSV format, reviews explainable detection results, and manages alert workflow from a modern Security Operations Centre dashboard.

> **Scope and safety:** SENTINEL-X analyses only log files deliberately supplied by an authorised operator. It does not scan networks, exploit systems, collect credentials, perform IP geolocation, or prove that a system has been compromised. Alerts are investigation leads that require human validation.

## Repository structure

```text
sentinel-x-threat-detection/
├── frontend/                 # React administrator dashboard
│   ├── index.html
│   ├── package.json
│   └── src/
│       ├── App.jsx
│       ├── main.jsx
│       └── styles.css
├── backend/                  # FastAPI application and detection logic
│   ├── app/
│   │   ├── database.py
│   │   ├── detection.py
│   │   ├── main.py
│   │   └── security.py
│   ├── sample_data/
│   ├── tests/
│   └── requirements.txt
├── database/                 # Database schema and local SQLite data
│   ├── schema.sql
│   └── README.md
├── docs/
└── .github/workflows/
```

## Architecture

| Layer | Responsibility | Technology |
|---|---|---|
| Frontend | Admin sign-in, dashboard, event ledger, alerts and reports | React, Vite, Recharts, Lucide |
| Backend | Authentication, CSV validation, API and detection orchestration | Python, FastAPI, Pydantic |
| Database | Persistent event and alert records | SQLite, SQL schema |
| Detection | Explainable authentication event rules | Python |
| Quality | Automated tests and frontend build | Pytest, GitHub Actions |

The SQLite database file is created at `database/sentinel_x.sqlite3` on first backend startup. The schema is version-controlled in `database/schema.sql`; the generated database file is excluded from Git.

## Implemented capabilities
- Administrator sign-in gate; API endpoints require HTTP Basic credentials.
- Dashboard with event metrics, activity chart, severity summary and recent events.
- CSV upload with a 5 MB limit, 10,000-record limit, required-column checks, ISO timestamp parsing and IP address validation.
- Detection rules for repeated authentication failures and successful authentication following repeated failures.
- SQLite persistence for imported events and generated alerts.
- Alert lifecycle management: open, investigating, resolved and false positive.
- Searchable event ledger, alert filtering and printable analysis summary.
- FastAPI interactive API documentation, protected by administrator credentials.

## Technology
- Frontend: React, Vite, Recharts and Lucide.
- Backend: Python, FastAPI and Pydantic.
- Database: SQLite.
- Tests: Pytest.
- Source control and CI: GitHub Actions.

## Requirements
- Python 3.10 or newer.
- Node.js 20 or newer and npm.

## Configure administrator credentials

Set credentials in the same terminal session before starting the backend. Use your own strong password; do not commit credentials to Git.

**Windows PowerShell**
```powershell
$env:SENTINEL_ADMIN_USERNAME = "admin"
$env:SENTINEL_ADMIN_PASSWORD = "replace-with-a-long-unique-password"
```

**Linux/macOS**
```bash
export SENTINEL_ADMIN_USERNAME="admin"
export SENTINEL_ADMIN_PASSWORD="replace-with-a-long-unique-password"
```

The backend deliberately refuses authenticated API access when these environment variables are missing. The browser stores the Basic-auth token in session storage for the current tab session and clears it when the administrator signs out.

## Run locally

### Backend — Windows PowerShell
```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:SENTINEL_ADMIN_USERNAME = "admin"
$env:SENTINEL_ADMIN_PASSWORD = "replace-with-a-long-unique-password"
uvicorn app.main:app --reload
```

### Backend — Linux/macOS
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export SENTINEL_ADMIN_USERNAME="admin"
export SENTINEL_ADMIN_PASSWORD="replace-with-a-long-unique-password"
uvicorn app.main:app --reload
```

The API is available at http://localhost:8000. Interactive documentation is at http://localhost:8000/docs and also requires administrator credentials.

### Frontend — open a second terminal at the repository root
```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173 and sign in using the administrator credentials configured in the backend terminal. The frontend expects the API at http://localhost:8000 by default. For a different API host, define `VITE_API_URL`.

## Demonstration dataset

Upload `backend/sample_data/sample_authentication_logs.csv` from the dashboard. Its IP addresses are reserved documentation examples (RFC 5737).

Required CSV columns: `timestamp,ip_address,username,event_type,status`.

- timestamp: ISO 8601 date-time, preferably UTC.
- ip_address: valid IPv4 or IPv6 address.
- username: account label recorded by the source system.
- event_type: use `login`, `authentication` or `auth` for authentication rules.
- status: failed / failure / denied / invalid or success / successful / accepted / ok.

## Detection rules

| Rule | Logic | Severity |
|---|---|---|
| AUTH-001 | Five or more failed authentication records from one source IP in the uploaded dataset | Medium; high at ten or more |
| AUTH-002 | A successful authentication record after at least five failures from the same source IP in the dataset | High |

The rules operate on the uploaded dataset as a whole. They do not currently implement a rolling time window or correlate events across separate uploads. Findings are indicators, not proof of compromise.

## API reference

All endpoints require HTTP Basic administrator authentication.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Protected service health |
| GET | `/api/dashboard` | Dashboard aggregates |
| POST | `/api/logs/upload` | Validate, analyse and store a CSV |
| GET | `/api/events` | List imported events |
| GET | `/api/alerts` | List alerts; optional status filter |
| PATCH | `/api/alerts/{alert_id}` | Update alert workflow status |
| GET | `/api/reports` | Summary counts |

## Tests
From the backend directory:
```bash
pip install -r requirements.txt
pytest
```

## Security and operational notes
- This is an educational local prototype, not a production SIEM.
- HTTP Basic authentication must be protected by HTTPS in any network deployment. Do not expose the development server publicly.
- The current prototype does not implement multi-user accounts, password hashing/rotation, role administration, CSRF protections, audit logging, rate limiting, TLS termination or production secrets management.
- Do not upload passwords, access tokens, session cookies or unnecessary personal data.
- Use only datasets you are authorised to process.
- Before production use, implement a reviewed identity provider or secure session system, HTTPS, audit trails, rate limits, secure secret storage, backups, retention controls and a security assessment.

## Submission information
Complete your verified developer details in [docs/project-information.md](docs/project-information.md) before submitting. Do not invent a CTC ID.
