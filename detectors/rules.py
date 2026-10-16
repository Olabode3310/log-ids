def detect_rules(events,config):
 alerts=[]
 for e in events:
  msg=e.get('message','').lower();ua=e.get('user_agent','').lower();port=str(e.get('port',''))
  if any(x in msg for x in ('failed password','authentication failure','invalid user')):
   alerts.append(alert('failed_login','medium','Authentication failure observed',e))
  for term in config.get('suspicious_user_agents',[]):
   if term.lower() in ua:alerts.append(alert('suspicious_user_agent','medium',f'Suspicious user-agent contains {term}',e));break
  if port and port in {str(x) for x in config.get('unusual_ports',[])}:alerts.append(alert('unusual_port','low',f'Event references configured unusual port {port}',e))
  if e.get('status') in (401,403):alerts.append(alert('denied_request','low',f'HTTP status {e["status"]}',e))
 return alerts
def alert(rule,severity,message,event):return {'rule':rule,'severity':severity,'message':message,'event':event}
