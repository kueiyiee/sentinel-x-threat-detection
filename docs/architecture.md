# SENTINEL-X — Technical Architecture

## Repository layout
- `frontend/`: React administrator interface and presentation layer.
- `backend/`: FastAPI application, administrator authentication, CSV validation and detection logic.
- `database/`: version-controlled SQLite schema and runtime database file.
- `docs/`: project, architecture and demonstration documentation.

## Request flow
1. Administrator signs in through the frontend.
2. Frontend sends HTTP Basic credentials to the protected API.
3. FastAPI validates the configured administrator username and password using constant-time comparisons.
4. The administrator imports a CSV file through the React interface.
5. API validates file type, size, required fields and maximum row count.
6. Detection service normalises timestamps, validates IP addresses and event status, then applies deterministic rules.
7. Valid events and generated alerts are stored in SQLite.
8. React retrieves statistics, events and alerts through authenticated API requests.

## Database
The schema is maintained in `database/schema.sql`. On first backend startup, SQLite creates `database/sentinel_x.sqlite3` automatically. The generated database is local runtime data and must not be committed to source control.

## Authentication boundary
All FastAPI routes require administrator credentials. The username and password are read from `SENTINEL_ADMIN_USERNAME` and `SENTINEL_ADMIN_PASSWORD` environment variables. If either is missing, API access is unavailable. The frontend retains the encoded Basic-auth token in browser session storage and clears it on sign-out.

HTTP Basic authentication is acceptable only for this controlled local educational demonstration. It must be transported over HTTPS and replaced with a reviewed identity/session solution before network or production deployment. This prototype has one configured administrator identity, not a multi-user account management system.

## Detection logic
- AUTH-001: five or more failed authentication events from one source IP in the submitted dataset. Medium severity; high severity at ten or more.
- AUTH-002: a successful authentication event follows at least five failures from the same source IP in the submitted dataset. High severity.

These are heuristic indicators, not definitive evidence of malicious activity. They currently operate over the complete uploaded dataset rather than a rolling time interval.

## Trust boundaries and limitations
CSV input is untrusted. File size, row count, required fields, timestamp format, IP syntax and status values are validated. SQL statements use bound parameters. CORS is restricted to the local Vite development origins.

The prototype does not implement TLS termination, multi-user RBAC, audit logging, rate limiting, password hashing/rotation, production secrets management or a production deployment configuration. Keep it local for the educational demonstration.
