# SENTINEL-X — Technical Architecture

## Components
- **React/Vite client:** presents dashboard, event ledger, alerts, search, filters and CSV import.
- **FastAPI service:** validates incoming files, exposes JSON endpoints and coordinates analysis.
- **Detection service:** validates timestamps and IP addresses, normalises event status and applies deterministic authentication rules.
- **SQLite store:** persists imported events and alert workflow state.

## Data flow
1. Operator selects a CSV file in the browser.
2. Client sends multipart form data to POST /api/logs/upload.
3. API checks CSV extension, 5 MB maximum size, required columns and 10,000-row maximum.
4. Detection service normalises records and rejects invalid timestamps, IP addresses or status values.
5. Rules AUTH-001 and AUTH-002 evaluate authentication events grouped by source IP.
6. API stores the validated events and generated alerts in SQLite.
7. React refreshes dashboard, events and alerts through read endpoints.

## Detection logic
- AUTH-001: five or more failed authentication events from one source IP in the submitted dataset. Medium severity; high severity at ten or more.
- AUTH-002: a successful authentication event follows at least five failures from the same source IP in the submitted dataset. High severity.

These are heuristic indicators, not definitive evidence of malicious activity. They currently operate over the complete uploaded dataset rather than a rolling time interval.

## Data model
- events: timestamp, source IP, username, event type, status and generated record ID.
- alerts: rule ID, title, explanation, severity, source IP, username, event count, first/last observation and analyst workflow status.

## Trust boundaries and limitations
The uploaded CSV is untrusted input. File size, row count, required fields, timestamp format, IP syntax and status values are validated. SQL statements use bound parameters. CORS is limited to the local Vite development origins.

The application currently has no authentication, authorisation, audit trail, rate limiting, TLS termination or production secrets management. Keep it local for the educational demonstration. Do not expose it to untrusted networks or process sensitive logs without appropriate controls.
