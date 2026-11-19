import csv
import io
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from .database import connect, init_db
from .detection import analyse_events
from .security import require_admin

app = FastAPI(
    title="SENTINEL-X API",
    description="Administrator-protected defensive security event analysis API.",
    version="1.1.0",
    dependencies=[Depends(require_admin)],
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)

@app.on_event("startup")
def startup():
    init_db()

class StatusUpdate(BaseModel):
    status: str = Field(pattern="^(open|investigating|resolved|false_positive)$")

@app.get("/")
def root():
    return {"name": "SENTINEL-X", "version": "1.1.0", "docs": "/docs"}

@app.get("/api/health")
def health():
    return {"status": "healthy", "service": "sentinel-x-api", "access": "administrator"}

@app.post("/api/logs/upload")
async def upload_logs(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(400, "Upload a CSV file.")
    raw = await file.read(5 * 1024 * 1024 + 1)
    if len(raw) > 5 * 1024 * 1024:
        raise HTTPException(413, "CSV exceeds the 5 MB limit.")
    try:
        reader = csv.DictReader(io.StringIO(raw.decode("utf-8-sig")))
        required = {"timestamp", "ip_address", "username", "event_type", "status"}
        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
            raise ValueError("Required columns: timestamp, ip_address, username, event_type, status.")
        rows = list(reader)
        if not rows or len(rows) > 10000:
            raise ValueError("CSV must contain 1–10,000 records.")
        events, alerts = analyse_events(rows)
    except (UnicodeDecodeError, csv.Error, ValueError) as error:
        raise HTTPException(400, f"Invalid CSV: {error}") from error
    with connect() as connection:
        connection.executemany(
            "INSERT INTO events(timestamp,ip_address,username,event_type,status) VALUES(?,?,?,?,?)",
            [(event["timestamp"], event["ip_address"], event["username"], event["event_type"], event["status"]) for event in events],
        )
        for alert in alerts:
            connection.execute(
                """INSERT INTO alerts(rule_id,title,description,severity,source_ip,username,event_count,first_seen,last_seen)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (alert["rule_id"], alert["title"], alert["description"], alert["severity"], alert["source_ip"],
                 alert["username"], alert["event_count"], alert["first_seen"], alert["last_seen"]),
            )
    return {"message": "Analysis completed", "events_imported": len(events), "alerts_created": len(alerts), "alerts": alerts}

@app.get("/api/dashboard")
def dashboard():
    with connect() as connection:
        total = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        alert_count = connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        open_count = connection.execute("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0]
        failed = connection.execute("SELECT COUNT(*) FROM events WHERE status IN ('failed','failure','denied','invalid')").fetchone()[0]
        severity = {row["severity"]: row["count"] for row in connection.execute("SELECT severity,COUNT(*) count FROM alerts GROUP BY severity")}
        recent = [dict(row) for row in connection.execute("SELECT * FROM events ORDER BY id DESC LIMIT 8")]
        timeline = [dict(row) for row in connection.execute("SELECT substr(timestamp,1,10) day,COUNT(*) events FROM events GROUP BY day ORDER BY day DESC LIMIT 7")]
    return {"total_events": total, "total_alerts": alert_count, "open_alerts": open_count,
            "failed_logins": failed, "severity": severity, "recent_events": recent, "timeline": list(reversed(timeline))}

@app.get("/api/events")
def get_events(limit: int = 100):
    limit = max(1, min(limit, 500))
    with connect() as connection:
        return [dict(row) for row in connection.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))]

@app.get("/api/alerts")
def get_alerts(status: str | None = None):
    if status and status not in {"open", "investigating", "resolved", "false_positive"}:
        raise HTTPException(400, "Invalid status filter.")
    with connect() as connection:
        rows = connection.execute("SELECT * FROM alerts WHERE status=? ORDER BY id DESC", (status,)) if status else connection.execute("SELECT * FROM alerts ORDER BY id DESC")
        return [dict(row) for row in rows]

@app.patch("/api/alerts/{alert_id}")
def update_alert(alert_id: int, update: StatusUpdate):
    with connect() as connection:
        cursor = connection.execute("UPDATE alerts SET status=? WHERE id=?", (update.status, alert_id))
        if cursor.rowcount == 0:
            raise HTTPException(404, "Alert not found.")
        return dict(connection.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone())

@app.get("/api/reports")
def reports():
    with connect() as connection:
        events = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        alerts = connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        severity = [dict(row) for row in connection.execute("SELECT severity,COUNT(*) count FROM alerts GROUP BY severity")]
    return {"events_analysed": events, "alerts_generated": alerts, "severity_breakdown": severity}
