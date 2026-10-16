import csv,re
from datetime import datetime
AUTH=re.compile(r'^(?P<ts>\w+\s+\d+\s+[\d:]+)\s+(?P<host>\S+)\s+(?P<program>[^:[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$')
ACCESS=re.compile(r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^]]+)\] "(?P<method>\S+) (?P<path>\S+) [^"]+" (?P<status>\d{3}) (?P<size>\S+)(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?')
def parse_line(line,kind):
 if kind=='auth':
  m=AUTH.match(line)
  if not m:return None
  d=m.groupdict();return {'source':'auth','timestamp':d['ts'],'host':d['host'],'program':d['program'].strip(),'message':d['message']}
 if kind=='access':
  m=ACCESS.match(line)
  if not m:return None
  d=m.groupdict();return {'source':'access','timestamp':d['ts'],'ip':d['ip'],'method':d['method'],'path':d['path'],'status':int(d['status']),'user_agent':d.get('ua') or ''}
 if kind=='csv':
  d=next(csv.DictReader([line]));return dict(d,source='csv')
 raise ValueError('kind must be auth, access, or csv')
def parse_file(path,kind):
 with open(path,encoding='utf-8',errors='replace',newline='') as f:
  if kind=='csv':
   for row in csv.DictReader(f):
    yield dict(row,source='csv')
   return
  for line in f:
   event=parse_line(line.rstrip(),kind)
   if event:yield event
