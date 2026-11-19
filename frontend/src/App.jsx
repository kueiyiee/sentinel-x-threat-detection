import { useEffect, useMemo, useState } from "react";
import { Activity, Shield, ShieldAlert, Upload, FileText, LayoutDashboard, Bell, RefreshCw, Search, CheckCircle2, AlertTriangle, Server, ChevronRight, LogOut, LockKeyhole, Eye, EyeOff, Database, Clock3 } from "lucide-react";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";
const nav = [["overview","Overview",LayoutDashboard],["events","Security events",Activity],["alerts","Alerts centre",Bell],["reports","Reports",FileText]];
const number = value => new Intl.NumberFormat().format(value || 0);
const failed = value => ["failed","failure","denied","invalid"].includes(String(value).toLowerCase());

function getSavedAuth() { try { return sessionStorage.getItem("sentinel_admin_auth") || ""; } catch { return ""; } }
function authHeaders(token, extra = {}) { return { ...extra, ...(token ? { Authorization: `Basic ${token}` } : {}) }; }

export default function App() {
  const [token,setToken] = useState(getSavedAuth);
  const [username,setUsername] = useState("");
  const [password,setPassword] = useState("");
  const [showPassword,setShowPassword] = useState(false);
  const [loginBusy,setLoginBusy] = useState(false);
  const [loginError,setLoginError] = useState("");
  const [page,setPage] = useState("overview");
  const [data,setData] = useState(null);
  const [alerts,setAlerts] = useState([]);
  const [events,setEvents] = useState([]);
  const [health,setHealth] = useState("checking");
  const [busy,setBusy] = useState(false);
  const [notice,setNotice] = useState("");
  const [query,setQuery] = useState("");
  const [filter,setFilter] = useState("all");

  async function api(path, options = {}) {
    const response = await fetch(API + path, { ...options, headers: authHeaders(token, options.headers || {}) });
    if (response.status === 401) { logout(); throw new Error("Your administrator session has expired. Sign in again."); }
    if (!response.ok) {
      let detail = "The request could not be completed.";
      try { const body = await response.json(); detail = body.detail || detail; } catch {}
      throw new Error(detail);
    }
    return response.json();
  }
  async function login(event) {
    event.preventDefault(); setLoginBusy(true); setLoginError("");
    const candidate = btoa(`${username.trim()}:${password}`);
    try {
      const response = await fetch(API + "/api/health", { headers: { Authorization: `Basic ${candidate}` } });
      if (!response.ok) {
        let message = "Sign-in failed. Check the administrator credentials and API configuration.";
        try { const body = await response.json(); message = body.detail || message; } catch {}
        throw new Error(message);
      }
      sessionStorage.setItem("sentinel_admin_auth", candidate);
      setToken(candidate); setPassword(""); setHealth("online");
    } catch (error) { setLoginError(error.message || "Unable to connect to the SENTINEL-X API."); }
    finally { setLoginBusy(false); }
  }
  function logout() {
    try { sessionStorage.removeItem("sentinel_admin_auth"); } catch {}
    setToken(""); setData(null); setAlerts([]); setEvents([]); setHealth("checking"); setPage("overview");
  }
  async function load() {
    try {
      const [dashboard, alertRows, eventRows] = await Promise.all([api("/api/dashboard"),api("/api/alerts"),api("/api/events")]);
      setData(dashboard); setAlerts(alertRows); setEvents(eventRows); setHealth("online");
    } catch (error) { if (!String(error.message).includes("session")) setHealth("offline"); }
  }
  useEffect(() => { if (!token) return; load(); const timer = setInterval(load,15000); return () => clearInterval(timer); }, [token]);
  async function upload(file) {
    if (!file) return; setBusy(true); setNotice("");
    try {
      const form = new FormData(); form.append("file",file);
      const result = await api("/api/logs/upload",{method:"POST",body:form});
      setNotice(`Analysis complete: ${result.events_imported} events imported and ${result.alerts_created} alerts generated.`);
      await load(); setPage("alerts");
    } catch (error) { setNotice(error.message); }
    finally { setBusy(false); }
  }
  async function updateStatus(id,value) {
    try { await api(`/api/alerts/${id}`,{method:"PATCH",headers:{"Content-Type":"application/json"},body:JSON.stringify({status:value})}); await load(); setNotice("Alert workflow status updated."); }
    catch (error) { setNotice(error.message); }
  }
  const visibleEvents = useMemo(() => events.filter(item => [item.ip_address,item.username,item.status].join(" ").toLowerCase().includes(query.toLowerCase())),[events,query]);
  const visibleAlerts = alerts.filter(item => (filter === "all" || item.status === filter) && [item.title,item.source_ip,item.username,item.severity].join(" ").toLowerCase().includes(query.toLowerCase()));
  const stats = [["Events analysed",number(data?.total_events),"Imported security records",Activity,"cyan"],["Alerts generated",number(data?.total_alerts),"Rule-based detections",ShieldAlert,"amber"],["Open incidents",number(data?.open_alerts),"Require analyst review",Bell,"red"],["Failed logins",number(data?.failed_logins),"Imported records",AlertTriangle,"violet"]];

  if (!token) return <div className="login-shell"><div className="login-orbit orbit-a"/><div className="login-orbit orbit-b"/><section className="login-card">
    <div className="login-brand"><div className="logo"><Shield size={25}/></div><div><b>SENTINEL<span>-X</span></b><small>SECURITY OPERATIONS PLATFORM</small></div></div>
    <div className="login-rule"><span/> ADMINISTRATOR ACCESS <span/></div>
    <h1>Command your<br/><em>security posture.</em></h1><p className="login-copy">Sign in to access the protected monitoring workspace, investigate alerts and review security telemetry.</p>
    <form onSubmit={login} className="login-form">
      <label>Administrator username<input autoComplete="username" value={username} onChange={e=>setUsername(e.target.value)} placeholder="Enter your administrator username" required/></label>
      <label>Password<div className="password-field"><input autoComplete="current-password" type={showPassword?"text":"password"} value={password} onChange={e=>setPassword(e.target.value)} placeholder="Enter your password" required/><button type="button" onClick={()=>setShowPassword(!showPassword)} aria-label="Toggle password visibility">{showPassword?<EyeOff size={16}/>:<Eye size={16}/>}</button></div></label>
      {loginError&&<div className="login-error"><AlertTriangle size={15}/>{loginError}</div>}
      <button className="login-submit" disabled={loginBusy}>{loginBusy?"Verifying access…":"Access admin dashboard"} <ChevronRight size={17}/></button>
    </form>
    <div className="login-foot"><LockKeyhole size={14}/> RESTRICTED ADMINISTRATOR AREA</div>
  </section><div className="login-caption">SENTINEL-X <span>·</span> DETECT. ANALYSE. DEFEND.</div></div>;

  return <div className="shell"><aside className="side">
    <div className="brand"><div className="logo"><Shield/></div><div><b>SENTINEL<span>-X</span></b><small>SECURITY OPERATIONS</small></div></div>
    <div className="workspace"><i/><div><b>Administrator workspace</b><small>Privileged access active</small></div></div>
    <label className="navlabel">COMMAND CENTRE</label><nav>{nav.map(([id,label,Icon])=><button key={id} className={page===id?"nav active":"nav"} onClick={()=>{setPage(id);setQuery("");}}><Icon size={17}/>{label}{page===id&&<ChevronRight className="push" size={15}/>}</button>)}</nav>
    <div className="side-bottom"><div className="sidefoot"><Shield size={18}/><div><b>Protected environment</b><small>Administrator access only</small></div></div><button className="logout" onClick={logout}><LogOut size={15}/> Sign out</button></div>
  </aside><main><header><div><div className="crumb">SENTINEL-X / COMMAND CENTRE / <span>{page.toUpperCase()}</span></div><h1>{nav.find(item=>item[0]===page)?.[1]}</h1></div><div className="actions"><span className={`api ${health}`}><i/> API {health}</span><button className="iconbtn" onClick={load} title="Refresh data"><RefreshCw size={16}/></button><label className="upload"><Upload size={15}/>{busy?"Analysing…":"Import logs"}<input type="file" accept=".csv,text/csv" hidden disabled={busy} onChange={event=>{upload(event.target.files?.[0]);event.target.value="";}}/></label><button className="admin-avatar" title="Administrator account"><LockKeyhole size={16}/></button></div></header>
    {notice&&<div className="notice">{notice}<button onClick={()=>setNotice("")}>Dismiss</button></div>}
    {health==="offline"&&<div className="offline"><Server size={17}/> API unavailable. Check the backend service and administrator environment variables.</div>}
    {page==="overview"&&<><section className="hero"><div><div className="kicker"><i/> THREAT MONITORING WORKSPACE</div><h2>See the signals.<br/><em>Stay ahead of threats.</em></h2><p>A centralised view of authentication telemetry, explainable detections and incident response activity — designed for security administrators.</p><div className="hero-meta"><span><LockKeyhole size={13}/> ADMIN CONTROL</span><span><Database size={13}/> LOCAL DATA STORE</span><span><Clock3 size={13}/> 15-SECOND REFRESH</span></div></div><div className="heroicon"><div className="ring r1"/><div className="ring r2"/><Shield size={65}/><small>DEFENCE / 01</small></div></section>
    <section className="stats">{stats.map(([label,value,sub,Icon,tone])=><article className="stat" key={label}><div className={`staticon ${tone}`}><Icon size={18}/></div><small>{label}</small><strong>{value}</strong><span>{sub}</span></article>)}</section>
    <section className="grid"><article className="panel"><div className="panelhead"><div><h3>Security event activity</h3><p>Imported records grouped by date</p></div><span className="tag">TELEMETRY</span></div><div className="chart">{data?.timeline?.length?<ResponsiveContainer width="100%" height="100%"><AreaChart data={data.timeline}><defs><linearGradient id="eventFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#51cbd8" stopOpacity=".32"/><stop offset="100%" stopColor="#51cbd8" stopOpacity="0"/></linearGradient></defs><CartesianGrid strokeDasharray="3 3" stroke="#263443"/><XAxis dataKey="day" stroke="#8292a5" tick={{fontSize:10}}/><YAxis stroke="#8292a5" tick={{fontSize:10}}/><Tooltip contentStyle={{background:"#111b27",border:"1px solid #344454",borderRadius:8}}/><Area dataKey="events" stroke="#58cedb" fill="url(#eventFill)" strokeWidth={2.4}/></AreaChart></ResponsiveContainer>:<Empty text="Import a CSV log to populate security analytics."/>}</div></article>
    <article className="panel"><div className="panelhead"><div><h3>Alert severity</h3><p>Detection distribution</p></div></div><div className="severity">{["critical","high","medium","low"].map(level=><div key={level}><i className={level}/><span>{level}</span><b>{number(data?.severity?.[level])}</b></div>)}</div><p className="footnote">Severity follows the documented detection rules. Every alert requires analyst validation.</p></article></section>
    <section className="panel"><div className="panelhead"><div><h3>Recent security events</h3><p>Latest imported authentication records</p></div><button className="linkbtn" onClick={()=>setPage("events")}>View event ledger <ChevronRight size={14}/></button></div><EventTable rows={data?.recent_events||[]}/></section></>}
    {page==="events"&&<section className="panel"><div className="panelhead"><div><h3>Security event ledger</h3><p>{events.length} records retrieved · latest first</p></div><SearchBox value={query} set={setQuery}/></div><EventTable rows={visibleEvents}/></section>}
    {page==="alerts"&&<section className="panel"><div className="panelhead"><div><h3>Detection and incident queue</h3><p>Review findings and manage investigation status</p></div><SearchBox value={query} set={setQuery}/></div><div className="filters">{["all","open","investigating","resolved","false_positive"].map(status=><button className={filter===status?"selected":""} key={status} onClick={()=>setFilter(status)}>{status.replace("_"," ")}</button>)}</div><div className="alertlist">{visibleAlerts.map(alert=><article className="alert" key={alert.id}><div className={`alerticon ${alert.severity}`}><ShieldAlert size={18}/></div><div className="alertbody"><b>{alert.title} <span className={`pill ${alert.severity}`}>{alert.severity}</span></b><p>{alert.description}</p><small>Source {alert.source_ip} · Account {alert.username} · Rule {alert.rule_id} · {alert.event_count} records</small></div><select value={alert.status} onChange={event=>updateStatus(alert.id,event.target.value)}><option value="open">Open</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option><option value="false_positive">False positive</option></select></article>)}{!visibleAlerts.length&&<Empty text="No alerts match the selected filters."/>}</div></section>}
    {page==="reports"&&<section className="panel"><div className="panelhead"><div><h3>Security analysis report</h3><p>Current local database snapshot</p></div><button className="upload" onClick={()=>window.print()}><FileText size={15}/> Print report</button></div><div className="reportgrid"><div><small>EVENTS ANALYSED</small><b>{number(data?.total_events)}</b></div><div><small>ALERTS GENERATED</small><b>{number(data?.total_alerts)}</b></div><div><small>OPEN INCIDENTS</small><b>{number(data?.open_alerts)}</b></div></div><p className="footnote">This report covers records imported into this instance. Rule-based findings are investigation indicators, not proof of compromise.</p></section>}
    <footer><span>© 2026 SENTINEL-X · DEFENSIVE CYBERSECURITY PROJECT</span><span>DETECT · ANALYSE · DEFEND</span></footer></main></div>;
}
function SearchBox({value,set}){return <label className="search"><Search size={14}/><input placeholder="Search IPs, accounts, status…" value={value} onChange={event=>set(event.target.value)}/></label>}
function Empty({text}){return <div className="empty"><Activity size={24}/><b>Nothing to display yet</b><span>{text}</span></div>}
function EventTable({rows}){return <div className="tablewrap"><table><thead><tr><th>TIMESTAMP</th><th>SOURCE IP</th><th>ACCOUNT</th><th>EVENT TYPE</th><th>RESULT</th></tr></thead><tbody>{rows.map(row=><tr key={row.id}><td>{row.timestamp?.replace("T"," ").replace("Z"," UTC")}</td><td className="mono">{row.ip_address}</td><td>{row.username}</td><td>{row.event_type}</td><td><span className={failed(row.status)?"failed":"success"}>{failed(row.status)?<AlertTriangle size={12}/>:<CheckCircle2 size={12}/>} {row.status}</span></td></tr>)}</tbody></table>{!rows.length&&<Empty text="Import an authorised CSV security log to begin."/>}</div>}
