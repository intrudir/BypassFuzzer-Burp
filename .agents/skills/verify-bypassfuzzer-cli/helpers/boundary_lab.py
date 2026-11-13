#!/usr/bin/env python3
from pathlib import Path
import socketserver,ssl,threading,time,json,signal,sys,subprocess,collections
import h2.config,h2.connection,h2.events
proof=Path(sys.argv[1]);private=Path(sys.argv[2]);cert=private/'fixture.crt';key=private/'fixture.key';trust=private/'trust.p12'
subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
key.chmod(0o600)
trust.unlink(missing_ok=True)
subprocess.run(['keytool','-importcert','-noprompt','-alias','fixture','-file',str(cert),'-keystore',str(trust),'-storepass','fixture-pass'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
rows=[];counts=collections.Counter();lock=threading.Lock();servers=[];ports={};running=True
class Server(socketserver.ThreadingTCPServer):allow_reuse_address=True;daemon_threads=True

def route(role,method,path,headers,protocol):
 fields={k.lower():v for k,v in headers};auth='authorization' in fields
 with lock:
  counts[(role,path,protocol)]+=1;attempt=counts[(role,path,protocol)]
  rows.append({'role':role,'method':method,'path':path,'protocol':protocol,'hasAuth':auth,'hasCookie':'cookie' in fields,'hasCustomSecret':'x-custom-secret' in fields,'userAgent':fields.get('user-agent',''),'headerNames':[k for k,v in headers],'attempt':attempt})
 if role=='empty09':return None,[],b''
 if role=='large09':return None,[],65
 if role=='body09':return None,[],b'body-only'
 if path=='/import/cross':return 302,[('Location',f"http://localhost:{ports['destination']}/spec")],b''
 if path=='/import/same':return 302,[('Location','/spec')],b''
 if path=='/import/discovery':return 200,[('Content-Type','text/html')],f"<html><script>SwaggerUIBundle({{url:'http://localhost:{ports['destination']}/spec'}})</script></html>".encode()
 if path=='/spec':return 200,[('Content-Type','application/json')],json.dumps({'openapi':'3.0.0','info':{'title':'owned','version':'1'},'servers':[{'url':f"http://127.0.0.1:{ports['origin']}"}],'paths':{'/imported':{'get':{'responses':{'200':{'description':'owned'}}}}}}).encode()
 if '/authretry/' in path:
  if auth or protocol=='HTTP/2':return 200,[('Content-Type','text/plain')],b'allowed'
  if '__bf_control_' in path:return 200,[('Content-Type','text/plain')],b'allowed'
  if path.startswith('/authretry/'):return 403,[('Content-Type','text/plain')],b'denied'
  healthy=attempt>1
  return (200 if healthy else 429),[('Content-Type','text/plain')],b'allowed' if healthy else b'limited'
 if '/protocol/' in path:
  status=200 if auth or protocol=='HTTP/2' or path.startswith('/v2/') else 403
  return status,[('Content-Type','text/plain')],b'allowed' if status==200 else b'denied'
 if '/retry/' in path or '/manual/' in path:
  if '__bf_control_' in path:return 200,[('Content-Type','text/plain')],b'allowed'
  if path.startswith('/retry/') or path.startswith('/manual/'):return 403,[('Content-Type','text/plain')],b'denied'
  healthy=(proof/'manual-healthy').exists() if '/manual/' in path else attempt>1
  return (200 if healthy else 429),[('Content-Type','text/plain')],b'allowed' if healthy else b'limited'
 return 403,[('Content-Type','text/plain')],b'denied'

def handler(role):
 class Handler(socketserver.StreamRequestHandler):
  def setup(self):self.request.settimeout(10);super().setup()
  def handle(self):
   try:
    if isinstance(self.request,ssl.SSLSocket) and self.request.selected_alpn_protocol()=='h2':return self.http2()
    line=self.rfile.readline(65536);parts=line.decode('iso-8859-1').strip('\r\n').split(' ',2)
    if len(parts)<2:return
    method,path=parts[:2];protocol=parts[2] if len(parts)==3 else 'HTTP/0.9';headers=[]
    if len(parts)==3:
     while True:
      line=self.rfile.readline(65536)
      if line in [b'',b'\r\n',b'\n']:break
      name,sep,value=line.decode('iso-8859-1').partition(':')
      if sep:headers.append((name.strip(),value.strip()))
    status,fields,body=route(role,method,path,headers,protocol)
    if status is None:
     if isinstance(body,int):
      for n in range(body):self.wfile.write(b'x'*1048576)
     else:self.wfile.write(body)
     return
    head=f'HTTP/1.1 {status} Result\r\n'+''.join(k+': '+v+'\r\n' for k,v in fields)+f'Content-Length: {len(body)}\r\nConnection: close\r\n\r\n'
    self.wfile.write(head.encode()+(b'' if method=='HEAD' else body))
   except (OSError,ValueError,ssl.SSLError):pass
  def http2(self):
   conn=h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=False,header_encoding='utf-8'));conn.initiate_connection();self.request.sendall(conn.data_to_send());streams={}
   try:
    while True:
     data=self.rfile.read1(65536)
     if not data:return
     for ev in conn.receive_data(data):
      if isinstance(ev,h2.events.RequestReceived):streams[ev.stream_id]=list(ev.headers)
      if isinstance(ev,h2.events.DataReceived):conn.acknowledge_received_data(ev.flow_controlled_length,ev.stream_id)
      if isinstance(ev,h2.events.StreamEnded):
       headers=streams.pop(ev.stream_id);fields=dict(headers);status,response,body=route(role,fields[':method'],fields[':path'],headers,'HTTP/2')
       head=[(':status',str(status)),('content-length',str(len(body)))]+[(k.lower(),v) for k,v in response]
       conn.send_headers(ev.stream_id,head,end_stream=not body)
       if body:conn.send_data(ev.stream_id,body,end_stream=True)
     self.request.sendall(conn.data_to_send())
   except (OSError,ValueError,ssl.SSLError):pass
 return Handler

def start(role,tls=False):
 server=Server(('127.0.0.1',0),handler(role))
 if tls:
  ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(cert,key);ctx.set_alpn_protocols(['h2','http/1.1']);server.socket=ctx.wrap_socket(server.socket,server_side=True)
 servers.append(server);threading.Thread(target=server.serve_forever,daemon=True).start();return server.server_address[1]
for role in ['origin','destination','empty09','large09','body09']:ports[role]=start(role)
ports['tls']=start('tls',True)
(proof/'ports.json').write_text(json.dumps(ports))
def stop(*args):
 global running
 running=False
signal.signal(signal.SIGTERM,stop)
def snapshot():
 with lock:return list(rows)
try:
 while running:
  file=proof/'observations.json.tmp';file.write_text(json.dumps(snapshot(),indent=2));file.replace(proof/'observations.json');time.sleep(.2)
finally:
 for server in servers:server.shutdown();server.server_close()
 (proof/'observations.json').write_text(json.dumps(snapshot(),indent=2))
