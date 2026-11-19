import os, sqlite3
from pathlib import Path
DB_PATH=Path(os.getenv('SENTINEL_DB_PATH',Path(__file__).resolve().parents[1]/'sentinel.db'))
def connect():
    DB_PATH.parent.mkdir(parents=True,exist_ok=True)
    c=sqlite3.connect(DB_PATH,timeout=10); c.row_factory=sqlite3.Row
    return c
def init_db():
    with connect() as c:
        c.executescript('''CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,timestamp TEXT NOT NULL,ip_address TEXT NOT NULL,username TEXT NOT NULL,event_type TEXT NOT NULL,status TEXT NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP); CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp); CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY,rule_id TEXT NOT NULL,title TEXT NOT NULL,description TEXT NOT NULL,severity TEXT NOT NULL CHECK(severity IN ('low','medium','high','critical')),source_ip TEXT NOT NULL,username TEXT NOT NULL,event_count INTEGER NOT NULL,first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','investigating','resolved','false_positive')),created_at TEXT DEFAULT CURRENT_TIMESTAMP); CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);''')
