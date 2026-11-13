#!/usr/bin/env python3
"""Packaged-CLI regressions using an owned TLS/HTTP1/HTTP2 fixture and fresh evidence."""
from pathlib import Path
import hashlib,json,os,shutil,subprocess,sys,tempfile,time
jar=Path(sys.argv[1]).resolve();e=Path(sys.argv[2]).resolve();e.mkdir(parents=True,exist_ok=True)
lab=None
for executable in ['java', 'keytool', 'openssl']:
 assert shutil.which(executable), 'Boundary verification requires '+executable
import importlib.util
assert importlib.util.find_spec('h2'), 'Boundary verification requires the Python h2 package'

def execute(name,args,expected=0):
 case=e/name;case.mkdir(exist_ok=True);(case/'command.json').write_text(json.dumps(args,indent=2))
 with (case/'stdout.log').open('w') as out,(case/'stderr.log').open('w') as err:
  result=subprocess.run(args,stdout=out,stderr=err,timeout=120)
 assert result.returncode==expected,(name,result.returncode,(case/'stderr.log').read_text()[-1600:])
 return case

def scan(name,mode,origin,path,flags=(),trust=False,auth=False):
 case=e/name;case.mkdir(exist_ok=True);request=case/'input.raw'
 request.write_bytes(f'GET {path} HTTP/1.1\r\nHost: {origin.split("://",1)[1]}\r\n{("Authorization: Bearer fixture"+chr(13)+chr(10)) if auth else ""}User-Agent: Boundary-Verification-UA\r\n\r\n'.encode())
 command=['java','-Xmx512m','-Djava.net.preferIPv4Stack=true']
 if trust:command += ['-Djavax.net.ssl.trustStore='+str(private/'trust.p12'),'-Djavax.net.ssl.trustStorePassword=fixture-pass']
 command += ['-jar',str(jar),mode,'--request',str(request),'--target-origin',origin,'--playbooks','bypass.path.api_prefix',
  '--max-probes','1','--retry-attempts','0','--no-wildcard-calibration','--request-timeout','4','--connect-timeout','2','--redact',*flags,'--output',str(case/'scan')]
 # Later flags intentionally override only defaults assembled here, through a single effective value.
 for flag in ['--max-probes','--retry-attempts']:
  while command.count(flag)>1:
   i=command.index(flag);del command[i:i+2]
 if '--wildcard-calibration' in command:command.remove('--no-wildcard-calibration')
 execute(name,command)
 summary=json.loads((case/'scan/summary.json').read_text());rows=[json.loads(s) for s in (case/'scan/results.jsonl').read_text().splitlines()]
 assert summary['state']=='completed',summary
 for row in rows:
  for field in ['requestRef','responseRef']:
   if row.get(field):assert (case/'scan'/row[field]).read_bytes()
 if os.name=='posix':assert (case/'scan/results.jsonl').stat().st_mode&0o077==0
 return summary,rows,case

try:
 with tempfile.TemporaryDirectory(prefix='bypass-boundary-private-') as scratch:
  private=Path(scratch);lab=subprocess.Popen([sys.executable,str(Path(__file__).with_name('boundary_lab.py')),str(e),str(private)],stdout=(e/'lab.log').open('w'),stderr=subprocess.STDOUT)
  end=time.monotonic()+30
  while not (e/'ports.json').exists():
   assert lab.poll() is None,(e/'lab.log').read_text()
   assert time.monotonic()<end,'Fixture readiness timed out'
   time.sleep(.1)
  ports=json.loads((e/'ports.json').read_text());tls=ports['tls'];proof={}
  for name,host,protocol,insecure,trust,accept in [
   ('tls-valid','localhost','http1',False,True,True),
   ('tls-wrong-host','127.0.0.1','http1',False,True,False),
   ('tls-untrusted','localhost','http1',False,False,False),
   ('tls-insecure','127.0.0.1','http1',True,False,True),
   ('tls-h2-valid','localhost','http2',False,True,True),
   ('tls-h2-wrong-host','127.0.0.1','http2',False,True,False),
   ('tls-http09-valid','localhost','http0.9',False,True,True),
   ('tls-http09-wrong-host','127.0.0.1','http0.9',False,True,False)]:
   summary,rows,case=scan(name,'bypass',f'https://{host}:{tls}','/tls-check',['--protocol',protocol]+(['--insecure'] if insecure else []),trust)
   assert bool(summary['transportErrors']==0)==accept,(name,summary)
   assert all((row.get('status') is not None)==accept for row in rows),(name,rows)
   proof[name]={'records':len(rows),'transportErrors':summary['transportErrors'],'accepted':accept}
  for protocol in ['http1','both','http2']:
   name='authenticated-'+protocol
   summary,rows,case=scan(name,'sweep',f'https://127.0.0.1:{tls}','/authretry/cli-'+protocol,
    ['--protocol',protocol,'--sweep-mode','authenticated','--insecure','--max-probes','5','--retry-attempts','1','--wildcard-calibration'],auth=True)
   anonymous=[r for r in rows if r.get('controlRole')=='TARGET'];recovered=[r for r in rows if r['retryAttempt']>0 and r.get('controlRole')=='NONE']
   expectedSkipped=0 if protocol=='http1' else 1
   assert summary['skippedPublicEndpoints']==expectedSkipped,(protocol,summary)
   if protocol!='http2':
    assert len(recovered)==5 and summary['findings']==5,(protocol,summary)
    assert all(r['signal'].startswith('BYPASS?') and r['status']==200 and r['calibration']['assessment']=='MATCH' for r in recovered)
    assert anonymous[0]['protocol']=='http1' and anonymous[0]['status']==403
   if protocol!='http1':assert any(r['protocol']=='http2' and r['status']==200 for r in anonymous)
   proof[name]={'summary':summary,'recovered':len(recovered),'anonymousProtocols':[r['protocol'] for r in anonymous]}
  summary,rows,case=scan('blocked-retry','sweep',f"http://127.0.0.1:{ports['origin']}",'/retry/cli',
   ['--protocol','http1','--sweep-mode','imported','--max-probes','6','--retry-attempts','1','--wildcard-calibration'])
  recovered=[r for r in rows if r['retryAttempt']>0 and r.get('controlRole')=='NONE']
  assert len(recovered)==summary['findings']==5 and summary['deferredRetries']==0,summary
  assert all(r['status']==200 and r['signal']=='403 -> 200' and r['calibration']['assessment']=='MATCH' for r in recovered)
  proof['blocked-retry']={'summary':summary,'recovered':len(recovered)}
  for role in ['empty09','large09','body09']:
   summary,rows,case=scan(role,'bypass',f'http://127.0.0.1:{ports[role]}','/http09-check',['--protocol','http0.9'])
   if role=='body09':assert summary['transportErrors']==0 and all(row['status']==200 and row['length']==9 for row in rows)
   else:
    assert summary['transportErrors']==len(rows)>0 and summary['findings']==0
    assert all(row.get('status') is None for row in rows)
    if role=='large09':assert all('Response exceeded 67108864 bytes' in row.get('error','') for row in rows)
   proof[role]={'records':len(rows),'transportErrors':summary['transportErrors']}
  source=e/'tls-valid/scan/results.jsonl';original=source.read_bytes();aliases=[source,source.parent/'../scan/results.jsonl']
  unsupported=[]
  for kind in ['hardlink','symlink']:
   alias=source.parent/(kind+'.jsonl')
   try:
    if kind=='hardlink':os.link(source,alias)
    else:alias.symlink_to(source)
    aliases.append(alias)
   except (OSError,NotImplementedError):unsupported.append(kind)
  for index,alias in enumerate(aliases):
   execute('export-collision-'+str(index),['java','-jar',str(jar),'results','--input',str(source.parent),'--output',str(alias),'--format','jsonl'],2)
   assert source.read_bytes()==original
  target=source.parent/'filtered.jsonl';execute('export-valid',['java','-jar',str(jar),'results','--input',str(source),'--output',str(target),'--format','jsonl'])
  assert source.read_bytes()==original and target.read_bytes()
  proof['export']={'aliasesRejected':len(aliases),'unsupportedAliases':unsupported,'inputSHA256':hashlib.sha256(original).hexdigest(),'inputUnchanged':True,'newOutputWorks':True}
  lab.terminate();lab.wait(timeout=10);lab=None
  (e/'assertions.json').write_text(json.dumps({'state':'PASS','artifactSHA256':hashlib.sha256(jar.read_bytes()).hexdigest(),'cases':proof},indent=2))
  print('PASS packaged CLI security boundaries:',len(proof),'cases',flush=True)
finally:
 if lab is not None:
  lab.terminate()
  try:lab.wait(timeout=10)
  except subprocess.TimeoutExpired:lab.kill();lab.wait()
 (e/'cleanup.json').write_text(json.dumps({'ownedFixtureStopped':True,'temporaryTLSKeysDeleted':not ('private' in globals() and private.exists())},indent=2))
