# SENTINEL-X
## Intelligent Security Monitoring & Threat Detection Platform

**Tagline:** Detect. Analyse. Defend.  
**Version:** 1.0.0  
**Project type:** Individual educational cybersecurity project

SENTINEL-X is a defensive security event analysis application. An authorised operator imports structured authentication logs in CSV format; the backend validates and normalises the records, applies explainable detection rules, stores events and alerts in SQLite, and presents the results in a React dashboard.

> **Scope and safety:** SENTINEL-X analyses only log files deliberately supplied by an authorised operator. It does not scan networks, exploit systems, collect credentials, perform IP geolocation, or prove that a system has been compromised. Alerts are investigation leads that require human validation.

## Implemented capabilities
- React dashboard with event metrics, date-grouped activity chart and alert severity summary.
- CSV upload with a 5 MB limit, a 10,000-record limit, required-column checks, ISO timestamp parsing and IP address validation.
- Python detection rules for repeated authentication failures and successful authentication following repeated failures.
- SQLite persistence for imported events and generated alerts.
- Alert lifecycle management: open, investigating, resolved and false positive.
- Searchable event ledger, alert filtering and printable analysis summary.
- FastAPI interactive API documentation.

## Technology
| Layer | Technology |
|---|---|
| Frontend | React, Vite, Recharts, Lucide |
| Backend | Python, FastAPI, Pydantic |
| Database | SQLite |
| Detection | Deterministic Python rules |
| Tests | Pytest |
| Source control | Git and GitHub |

## Architecture
1. The operator imports a CSV file through the React interface.
2. FastAPI validates file type, size, required fields and row count.
3. The detection service normalises timestamps and validates IP addresses and event status values.
4. Explainable rules analyse authentication events grouped by source IP.
5. Valid events and generated alerts are stored in SQLite using parameterised SQL.
6. The dashboard retrieves statistics, events and alerts through the API.

See [docs/architecture.md](docs/architecture.md) for further detail.

## Requirements
- Python 3.10 or newer.
- Node.js 20 or newer and npm.

## Run locally

### Backend — Windows PowerShell
```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### Backend — Linux/macOS
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

The API is available at http://localhost:8000 and interactive documentation at http://localhost:8000/docs.

### Frontend — open a second terminal at the repository root
```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173. The frontend expects the API at http://localhost:8000 by default. For a different API host, define `VITE_API_URL` in the frontend environment.

## Demonstration dataset
Upload `backend/sample_data/sample_authentication_logs.csv` from the dashboard. Its IP addresses belong to documentation-only example ranges reserved for sample configurations (RFC 5737); they do not identify real hosts.

Required CSV columns:
`timestamp,ip_address,username,event_type,status`

- `timestamp`: ISO 8601 date-time, preferably UTC.
- `ip_address`: valid IPv4 or IPv6 address.
- `username`: account label recorded by the source system.
- `event_type`: use `login`, `authentication` or `auth` for authentication rules.
- `status`: failed / failure / denied / invalid or success / successful / accepted / ok.

## Detection rules
| Rule | Logic | Severity |
|---|---|---|
| AUTH-001 | Five or more failed authentication records from one source IP in the uploaded dataset | Medium; high at ten or more |
| AUTH-002 | A successful authentication record after at least five failures from the same source IP in the dataset | High |

The rules operate on the uploaded dataset as a whole. They do not currently implement a rolling time window or correlate events across separate uploads. The system does not infer attacker identity or intent. Analysts must validate every finding against the relevant environment and context.

## API reference
| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Service health |
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
- Do not upload logs containing passwords, access tokens, session cookies or unnecessary personal data.
- Use only datasets you are authorised to process.
- The current prototype has no user authentication or role-based access control and is intended for local demonstration, not production deployment.
- Restrict network exposure and do not deploy publicly without authentication, authorisation, audit logging, secure configuration, backup and a formal security review.
- SQLite is suitable for this demonstration; a production deployment would need a reviewed data-retention and database strategy.

## Limitations and future work
The current release uses static rule-based analysis of CSV records. It is not a certified SIEM, does not ingest live endpoint telemetry, and does not provide threat attribution or machine-learning predictions. Future work may include authenticated analyst accounts, role-based access control, audit trails, streaming ingestion, configurable detection windows, alert deduplication, richer tests and signed report exports.

## Project submission information
Complete the individual developer details in [docs/project-information.md](docs/project-information.md) before submitting to INSA. Do not invent a CTC ID or publish private personal information unnecessarily.
