import os
import sqlite3
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DB_PATH = Path(os.getenv("SENTINEL_DB_PATH", PROJECT_ROOT / "database" / "sentinel_x.sqlite3"))
SCHEMA_PATH = PROJECT_ROOT / "database" / "schema.sql"

def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection

def init_db():
    if not SCHEMA_PATH.exists():
        raise RuntimeError(f"Database schema not found: {SCHEMA_PATH}")
    with connect() as connection:
        connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
