# Database Layer

This directory owns the SENTINEL-X persistence layer.

- `schema.sql`: version-controlled relational schema and indexes.
- `sentinel_x.sqlite3`: generated SQLite database created automatically by the backend at runtime; excluded from Git.

The backend initialises the schema on startup. Set `SENTINEL_DB_PATH` to override the default database file location.

Tables:
- `events`: imported authentication records.
- `alerts`: explainable rule detections and analyst workflow status.

Do not commit production data, sensitive logs, credentials or generated database files.
