import argparse,json,time
from pathlib import Path
from parsers.logs import parse_file
from detectors.rules import detect_rules
from detectors.anomaly import detect_anomalies

def load_config(path):return json.loads(Path(path).read_text(encoding='utf-8'))
def analyze(events,config):return detect_rules(events,config)+detect_anomalies(events,config)
def main():
 p=argparse.ArgumentParser(description='Rule-based log intrusion detection and batch anomaly summaries.')
 p.add_argument('file');p.add_argument('--type',choices=['auth','access','csv'],required=True);p.add_argument('--config',default='config.yaml');p.add_argument('--follow',action='store_true',help='Monitor appended lines; parse each line and report rule alerts');p.add_argument('--output',help='Write JSON alerts to this file');a=p.parse_args();cfg=load_config(a.config);events=list(parse_file(a.file,a.type));alerts=analyze(events,cfg)
 if a.follow:
  with open(a.file,encoding='utf8',errors='replace') as f:
   f.seek(0,2)
   try:
    while True:
     line=f.readline()
     if not line:time.sleep(.25);continue
     from parsers.logs import parse_line
     e=parse_line(line.rstrip(),a.type)
     if e:
      new=detect_rules([e],cfg)
      for x in new:print(json.dumps(x))
      alerts.extend(new)
   except KeyboardInterrupt:pass
 result={'events_analyzed':len(events),'alerts':alerts,'summary':{}}
 for x in alerts:result['summary'][x['severity']]=result['summary'].get(x['severity'],0)+1
 text=json.dumps(result,indent=2)
 if a.output:Path(a.output).write_text(text+'\n',encoding='utf8')
 else:print(text)
 return 0
if __name__=='__main__':raise SystemExit(main())
