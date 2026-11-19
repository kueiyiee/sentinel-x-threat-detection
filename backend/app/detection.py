from collections import defaultdict
from datetime import datetime,timezone
import ipaddress
FAILED={'failed','failure','denied','invalid'}; SUCCESS={'success','successful','accepted','ok'}
def parse_time(value):
    d=datetime.fromisoformat(value.strip().replace('Z','+00:00'))
    if d.tzinfo is None:d=d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc).isoformat().replace('+00:00','Z')
def analyse_events(rows):
    events=[]
    for n,r in enumerate(rows,1):
        try:
            ts=parse_time(str(r.get('timestamp',''))); ip=str(r.get('ip_address','')).strip(); ipaddress.ip_address(ip)
        except Exception as e: raise ValueError(f'Row {n}: invalid timestamp or IP address') from e
        status=str(r.get('status','')).strip().lower()
        if status not in FAILED|SUCCESS: raise ValueError(f'Row {n}: status must be failed or success')
        events.append({'timestamp':ts,'ip_address':ip,'username':str(r.get('username','unknown')).strip()[:128] or 'unknown','event_type':str(r.get('event_type','authentication')).strip().lower()[:64],'status':status})
    grouped=defaultdict(list)
    for e in events:
        if e['event_type'] in {'login','authentication','auth'}:grouped[e['ip_address']].append(e)
    alerts=[]
    for ip,items in grouped.items():
        items.sort(key=lambda x:x['timestamp']); fails=[e for e in items if e['status'] in FAILED]
        if len(fails)>=5:
            alerts.append({'rule_id':'AUTH-001','title':'Repeated authentication failures','description':f'{len(fails)} failed authentication records from this source IP appear in the uploaded dataset. Review related account activity.','severity':'high' if len(fails)>=10 else 'medium','source_ip':ip,'username':fails[-1]['username'],'event_count':len(fails),'first_seen':fails[0]['timestamp'],'last_seen':fails[-1]['timestamp']})
        prior=[]
        for e in items:
            if e['status'] in FAILED:prior.append(e)
            elif e['status'] in SUCCESS and len(prior)>=5:
                alerts.append({'rule_id':'AUTH-002','title':'Successful login after repeated failures','description':'A successful authentication follows multiple failures from the same source IP in this dataset. Verify whether the activity was authorised.','severity':'high','source_ip':ip,'username':e['username'],'event_count':len(prior)+1,'first_seen':prior[0]['timestamp'],'last_seen':e['timestamp']}); break
    return events,alerts
