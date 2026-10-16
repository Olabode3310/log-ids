from collections import Counter
from .rules import alert
def detect_anomalies(events,config):
 alerts=[];fail=[e for e in events if any(x in e.get('message','').lower() for x in ('failed password','authentication failure','invalid user'))]
 threshold=int(config.get('failed_login_threshold',5))
 counts=Counter(e.get('host') or e.get('ip','unknown') for e in fail)
 for actor,n in counts.items():
  if n>=threshold:alerts.append(alert('failed_login_spike','high',f'{n} failed login events associated with {actor}',{'actor':actor,'count':n}))
 volume=int(config.get('event_volume_threshold',0))
 if volume and len(events)>=volume:alerts.append(alert('event_volume','medium',f'Batch contains {len(events)} events (threshold {volume})',{'count':len(events)}))
 return alerts
