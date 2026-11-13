#!/usr/bin/env python3
import http.server,json,pathlib,subprocess,threading,time,hashlib
import argparse
p=argparse.ArgumentParser();p.add_argument('--jar',type=pathlib.Path,required=True);p.add_argument('--evidence',type=pathlib.Path,required=True);args=p.parse_args()
out=args.evidence;out.mkdir(parents=True,exist_ok=True);jar=args.jar
control=out/'control.txt';control.write_text('');control.chmod(0o600);wire=[];throttled=False
class Lab(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  global throttled
  row={'time':time.monotonic(),'path':self.path,'ua':self.headers.get('User-Agent')};wire.append(row)
  limited=self.path!='/private' and not throttled
  if limited:
   throttled=True;control.write_text('pause');time.sleep(.25)
  code=429 if limited else 403 if self.path=='/private' else 200
  self.send_response(code)
  if limited:self.send_header('Retry-After','2')
  self.send_header('Content-Length','0');self.send_header('Connection','close');self.end_headers()
  if limited:row['throttledResponseAt']=time.monotonic()
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Lab);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
request=out/'seed.raw';request.write_bytes(f'GET /private HTTP/1.1\r\nHost: 127.0.0.1:{server.server_port}\r\n\r\n'.encode())
cmd=['java','-jar',str(jar),'bypass','--request',str(request),'--target-origin',f'http://127.0.0.1:{server.server_port}','--playbooks','bypass.path.api_prefix','--no-wildcard-calibration','--global-concurrency','1','--per-host-concurrency','1','--retry-attempts','1','--protocol','http1','--header','User-Agent: Before-review','--control-file',str(control),'--output',str(out/'scan')]
(out/'command.json').write_text(json.dumps(cmd,indent=2));process=None
try:
 with (out/'stdout.log').open('w') as stdout,(out/'stderr.log').open('w') as stderr:
  process=subprocess.Popen(cmd,stdout=stdout,stderr=stderr)
  end=time.monotonic()+15;status=control.with_name(control.name+'.status.json')
  while True:
   assert time.monotonic()<end,'paused status timed out'
   if status.exists():
    try:s=json.loads(status.read_text())
    except json.JSONDecodeError:continue
    if s['state']=='paused' and s['inFlight']==0:break
   time.sleep(.02)
  (out/'paused-status.json').write_text(json.dumps(s,indent=2))
  edit={'action':'apply-resume','commandId':'header-review','expectedRevision':0,'configuration':{'headers':['User-Agent: After-review']}}
  control.write_text(json.dumps(edit));process.wait(timeout=20);assert process.returncode==0
 queue=json.loads((out/'scan/retry-queue.json').read_text());rows=[json.loads(x) for x in (out/'scan/results.jsonl').read_text().splitlines()];after=next(r for r in wire if r['ua']=='After-review');failure=next(r for r in wire if 'throttledResponseAt' in r)
 result={'artifactSha256':hashlib.sha256(jar.read_bytes()).hexdigest(),'requests':len(wire),'queueEntriesAfterRecovery':len(queue['entries']),'queuedRequestRetainsBeforeHeader':any('Before-review' in json.dumps(r) for r in queue['entries']),'successfulRetryWithNewHeader':any(r['retryAttempt']>0 and r['status']==200 and 'After-review' in (out/'scan'/r['requestRef']).read_text() for r in rows),'millisecondsUntilNextSendAfterRetryAfter2s':round((after['time']-failure['throttledResponseAt'])*1000,2)}
 (out/'observed.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
 assert result['queueEntriesAfterRecovery']==0 and result['successfulRetryWithNewHeader'],result
 assert result['millisecondsUntilNextSendAfterRetryAfter2s']>=1800,result
finally:
 if process is not None and process.poll() is None:process.terminate();process.wait(timeout=5)
 server.shutdown();server.server_close();thread.join(timeout=3);(out/'wire.json').write_text(json.dumps(wire,indent=2));(out/'cleanup.json').write_text(json.dumps({'ownedProcessStopped':process is None or process.poll() is not None,'ownedServerClosed':True}))
