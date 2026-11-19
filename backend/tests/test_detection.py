from app.detection import analyse_events
def test_repeated_failures_create_alert():
 rows=[{'timestamp':f'2026-11-19T08:0{i}:00Z','ip_address':'192.0.2.1','username':'demo','event_type':'login','status':'failed'} for i in range(5)]
 events,alerts=analyse_events(rows); assert len(events)==5; assert any(a['rule_id']=='AUTH-001' for a in alerts)
def test_invalid_ip_is_rejected():
 rows=[{'timestamp':'2026-11-19T08:00:00Z','ip_address':'bad-ip','username':'demo','event_type':'login','status':'failed'}]
 try:analyse_events(rows); assert False,'Expected invalid IP'
 except ValueError:pass
