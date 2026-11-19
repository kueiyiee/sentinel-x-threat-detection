import csv,io
from fastapi import FastAPI,File,HTTPException,UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel,Field
from .database import connect,init_db
from .detection import analyse_events
app=FastAPI(title='SENTINEL-X API',description='Defensive security event analysis and incident review API.',version='1.0.0')
app.add_middleware(CORSMiddleware,allow_origins=['http://localhost:5173','http://127.0.0.1:5173'],allow_credentials=False,allow_methods=['GET','POST','PATCH'],allow_headers=['Content-Type'])
@app.on_event('startup')
def startup():init_db()
class StatusUpdate(BaseModel):status:str=Field(pattern='^(open|investigating|resolved|false_positive)$')
@app.get('/')
def root():return {'name':'SENTINEL-X','version':'1.0.0','docs':'/docs'}
@app.get('/api/health')
def health():return {'status':'healthy','service':'sentinel-x-api'}
@app.post('/api/logs/upload')
async def upload_logs(file:UploadFile=File(...)):
    if not file.filename or not file.filename.lower().endswith('.csv'):raise HTTPException(400,'Upload a CSV file.')
    raw=await file.read(5*1024*1024+1)
    if len(raw)>5*1024*1024:raise HTTPException(413,'CSV exceeds the 5 MB limit.')
    try:
        reader=csv.DictReader(io.StringIO(raw.decode('utf-8-sig'))); required={'timestamp','ip_address','username','event_type','status'}
        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):raise ValueError('Required columns: timestamp, ip_address, username, event_type, status.')
        rows=list(reader)
        if not rows or len(rows)>10000:raise ValueError('CSV must contain 1–10,000 records.')
        events,alerts=analyse_events(rows)
    except (UnicodeDecodeError,csv.Error,ValueError) as e:raise HTTPException(400,f'Invalid CSV: {e}') from e
    with connect() as c:
        c.executemany('INSERT INTO events(timestamp,ip_address,username,event_type,status) VALUES(?,?,?,?,?)',[(e['timestamp'],e['ip_address'],e['username'],e['event_type'],e['status']) for e in events])
        for a in alerts:c.execute('INSERT INTO alerts(rule_id,title,description,severity,source_ip,username,event_count,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?)',(a['rule_id'],a['title'],a['description'],a['severity'],a['source_ip'],a['username'],a['event_count'],a['first_seen'],a['last_seen']))
    return {'message':'Analysis completed','events_imported':len(events),'alerts_created':len(alerts),'alerts':alerts}
@app.get('/api/dashboard')
def dashboard():
    with connect() as c:
        total=c.execute('SELECT COUNT(*) FROM events').fetchone()[0]; ac=c.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]; op=c.execute("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0]; failed=c.execute("SELECT COUNT(*) FROM events WHERE status IN ('failed','failure','denied','invalid')").fetchone()[0]
        severity={r['severity']:r['n'] for r in c.execute('SELECT severity,COUNT(*) n FROM alerts GROUP BY severity')}; recent=[dict(r) for r in c.execute('SELECT * FROM events ORDER BY id DESC LIMIT 8')]; timeline=[dict(r) for r in c.execute('SELECT substr(timestamp,1,10) day,COUNT(*) events FROM events GROUP BY day ORDER BY day DESC LIMIT 7')]
    return {'total_events':total,'total_alerts':ac,'open_alerts':op,'failed_logins':failed,'severity':severity,'recent_events':recent,'timeline':list(reversed(timeline))}
@app.get('/api/events')
def get_events(limit:int=100):
    limit=max(1,min(limit,500))
    with connect() as c:return [dict(r) for r in c.execute('SELECT * FROM events ORDER BY id DESC LIMIT ?',(limit,))]
@app.get('/api/alerts')
def get_alerts(status:str|None=None):
    if status and status not in {'open','investigating','resolved','false_positive'}:raise HTTPException(400,'Invalid status filter.')
    with connect() as c:
        rows=c.execute('SELECT * FROM alerts WHERE status=? ORDER BY id DESC',(status,)) if status else c.execute('SELECT * FROM alerts ORDER BY id DESC')
        return [dict(r) for r in rows]
@app.patch('/api/alerts/{alert_id}')
def update_alert(alert_id:int,update:StatusUpdate):
    with connect() as c:
        cur=c.execute('UPDATE alerts SET status=? WHERE id=?',(update.status,alert_id))
        if cur.rowcount==0:raise HTTPException(404,'Alert not found.')
        return dict(c.execute('SELECT * FROM alerts WHERE id=?',(alert_id,)).fetchone())
@app.get('/api/reports')
def reports():
    with connect() as c:
        events=c.execute('SELECT COUNT(*) FROM events').fetchone()[0]; alerts=c.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]; sev=[dict(r) for r in c.execute('SELECT severity,COUNT(*) count FROM alerts GROUP BY severity')]
    return {'events_analysed':events,'alerts_generated':alerts,'severity_breakdown':sev}
