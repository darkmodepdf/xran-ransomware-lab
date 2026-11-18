"""Local authenticated inference/control service; standard library only."""
import argparse
from collections import deque
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import threading
import time
import uuid
from raneval.windows_stream import Model,Router

HERE=Path(__file__).resolve().parent
class State:
    def __init__(self,model_path):
        self.lock=threading.RLock();self.model_error=None
        try: model=Model(model_path)
        except (OSError,ValueError,KeyError,TypeError) as e: model=None;self.model_error=str(e)
        self.router=Router(model);self.commands=deque(maxlen=32);self.actors={};self.alerts=deque(maxlen=100);self.files={};self.errors=deque(maxlen=100);self.agent_seen=0;self.agent_id=None;self.jobs={};self.command_drops=0
        self.histories={};self.activity=deque(maxlen=96);self.activity_seq=0
        self.invalid_seen=set();self.restored_seen=set()
    def milestone(self,kind,job,message,**fields):
        self.activity_seq+=1
        self.activity.append(dict(id=self.activity_seq,time=time.time(),type=kind,job=job,message=message,**fields))
    def online(self): return time.time()-self.agent_seen<5
    def snapshot(self):
        with self.lock:
            payload=self.router.model.payload if self.router.model else {}
            actors=[dict(a,history=list(self.histories.get(a['actor'],()))) for a in self.actors.values()]
            return dict(model_available=self.router.model is not None,model_error=self.model_error,model_schema=payload.get('schema'),threshold=self.router.model.threshold if self.router.model else None,evaluation=payload.get('evaluation'),agent_online=self.online(),agent_id=self.agent_id,actors=actors,activity=list(self.activity),alerts=list(self.alerts),files=list(self.files.values()),errors=list(self.errors),jobs=list(self.jobs.values()),telemetry=dict(actors=len(self.router.actors),actor_capacity=self.router.max_actors,history_horizon=128,chart_history_limit=512,chart_actor_limit=8,rejected=self.router.rejected,queued_commands=len(self.commands),command_drops=self.command_drops),limitations=payload.get('limitations','Weak session labels and CAPE/native domain shift; changed, invalid and model suspicion are independent. No guaranteed recall.'))
    def control(self,data):
        if not isinstance(data,dict) or set(data)-{'action','kind','job'}: raise ValueError('unknown control fields')
        action=data.get('action')
        with self.lock:
            if not self.online(): raise ValueError('native agent offline')
            if len(self.commands)>=32: self.command_drops+=1;raise ValueError('command queue full')
            if action=='start':
                if data.get('kind') not in ('benign','destructive') or set(data)!={'action','kind'}: raise ValueError('allowlisted kind required')
                active=sum(j['status'] in ('queued','running','stopping') for j in self.jobs.values())
                if active>=4: raise ValueError('four worker limit reached')
                if len(self.jobs)>=128: raise ValueError('job history capacity reached; restart service')
                job=uuid.uuid4().hex;command=dict(action='start',kind=data['kind'],job=job);self.jobs[job]=dict(command,status='queued',created_at=time.time());self.commands.append(command);return self.jobs[job]
            if action=='stop':
                if set(data)!={'action','job'} or data.get('job') not in self.jobs: raise ValueError('known owned job required')
                if self.jobs[data['job']]['status'] not in ('queued','running','stopping'): raise ValueError('worker is no longer active')
                job=data['job'];self.jobs[job]['status']='stopping';self.commands.append(dict(action='stop',job=job));return self.jobs[job]
            raise ValueError('unknown action')
    def update(self,data):
        if not isinstance(data,dict) or set(data)-{'agent_id','event','evidence','job_status','error'}: raise ValueError('invalid update fields')
        aid=data.get('agent_id')
        if not isinstance(aid,str) or not 1<=len(aid)<=64: raise ValueError('agent identity required')
        with self.lock:
            if self.agent_id and self.agent_id!=aid and self.online(): raise ValueError('another agent is connected')
            evidence=data.get('evidence')
            if evidence is not None:
                if not isinstance(evidence,list) or len(evidence)>6: raise ValueError('bounded evidence list required')
                for item in evidence:
                    if not isinstance(item,dict) or set(item)!={'job','file','sha256','baseline_sha256','valid','changed','actor','bytes'}: raise ValueError('invalid evidence schema')
                    if item['job'] not in self.jobs or item['file'] not in [f'fixture-{i}.jsonl' for i in range(6)]: raise ValueError('invalid fixture reference')
                    if type(item['valid']) is not bool or type(item['changed']) is not bool or type(item['bytes']) is not int or not 0<=item['bytes']<=16384: raise ValueError('invalid fixture values')
                    for key in ('sha256','baseline_sha256'):
                        if not isinstance(item[key],str) or len(item[key])!=64 or any(c not in '0123456789abcdef' for c in item[key]): raise ValueError('invalid hash')
            status=data.get('job_status')
            if status is not None:
                if not isinstance(status,dict) or set(status)!={'job','status'} or status['job'] not in self.jobs or status['status'] not in ('running','stopped','completed','failed'): raise ValueError('invalid job status')
            if 'error' in data:
                if not isinstance(data['error'],str) or len(data['error'])>1024: raise ValueError('invalid error')
            first_alert=None
            if 'event' in data:
                e=data['event'];job=e.get('job') if isinstance(e,dict) else None
                if job not in self.jobs: raise ValueError('event for unowned job')
                result=self.router.add(e);previous=self.actors.get(e['actor'],{})
                scores=[v for v in (previous.get('peak_score'),result['score']) if v is not None]
                result.update(job=job,kind=self.jobs[job]['kind'],peak_score=max(scores) if scores else None,ever_alert=previous.get('ever_alert',False) or result['alert'])
                first=bool(result['alert'] and not previous.get('ever_alert',False))
                related=[f for f in evidence or [] if f['job']==job and f['actor']==e['actor']]
                invalid=sum(not f['valid'] for f in related) if related else None
                result.update(first_alert_seq=e['seq'] if first else previous.get('first_alert_seq'),first_alert_time=time.time() if first else previous.get('first_alert_time'),invalid_files_at_first_alert=invalid if first else previous.get('invalid_files_at_first_alert'))
                result['file_telemetry']={key:e.get(key) for key in ('op','requested_bytes','completed_bytes','byte_offset','file_size_before','file_size_after')}
                self.actors[e['actor']]=result
                history=self.histories.pop(e['actor'],deque(maxlen=512))
                history.append(dict(seq=e['seq'],score=result['score'],time=time.time(),op=e['op']))
                self.histories[e['actor']]=history
                while len(self.histories)>8:del self.histories[next(iter(self.histories))]
                if result['alert']: self.alerts.append(dict(result,time=time.time()))
                if first:first_alert=dict(actor=e['actor'],seq=e['seq'],score=result['score'])
            for item in evidence or []:
                key=item['job']+':'+item['file'];prior=self.files.get(key)
                context=dict(actor=item['actor'],file=item['file'])
                if 'event' in data:context['seq']=data['event']['seq']
                if not item['valid'] and key not in self.invalid_seen:
                    self.invalid_seen.add(key);self.milestone('file_invalid',item['job'],'Fixture became invalid',**context)
                elif item['valid'] and prior and not prior['valid'] and key not in self.restored_seen:
                    self.restored_seen.add(key);self.milestone('file_restored',item['job'],'Fixture returned to valid content',**context)
                self.files[key]=item
            if first_alert:self.milestone('model_alert',job,'Model flagged this process',**first_alert)
            if status is not None:
                prior_status=self.jobs[status['job']]['status'];new_status=status['status']
                self.jobs[status['job']]['status']=new_status
                if prior_status!=new_status:
                    milestone={'running':'worker_started','completed':'worker_completed','stopped':'worker_stopped','failed':'worker_failed'}[new_status]
                    self.milestone(milestone,status['job'],{'running':'Worker started','completed':'Worker completed','stopped':'Worker stopped','failed':'Worker failed'}[new_status])
            if 'error' in data: self.errors.append(dict(time=time.time(),message=data['error']))
            self.agent_id=aid;self.agent_seen=time.time()

def make_server(host,port,model_path,control_token,agent_token):
    if min(len(control_token),len(agent_token))<32 or control_token==agent_token: raise ValueError('distinct control/agent tokens of at least 32 characters required')
    state=State(model_path)
    class Handler(BaseHTTPRequestHandler):
        server_version='WindowsStreamingLab/1'
        def log_message(self,*args): pass
        def reply(self,status,value,content_type='application/json'):
            body=json.dumps(value,allow_nan=False).encode() if content_type=='application/json' else value
            self.send_response(status);self.send_header('Content-Type',content_type);self.send_header('Content-Length',str(len(body)));self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'");self.end_headers();self.wfile.write(body)
        def gate(self,agent=False):
            host_header=self.headers.get('Host','')
            if host_header not in (f'127.0.0.1:{self.server.server_port}',f'localhost:{self.server.server_port}','127.0.0.1:8767','localhost:8767'): self.reply(403,dict(error='invalid host'));return False
            origin=self.headers.get('Origin')
            if origin and origin not in ('http://'+host_header,): self.reply(403,dict(error='invalid origin'));return False
            expected='Bearer '+(agent_token if agent else control_token)
            if not hmac.compare_digest(self.headers.get('Authorization',''),expected): self.reply(401,dict(error='authentication required'));return False
            return True
        def do_GET(self):
            if self.path=='/api/health': self.reply(200,dict(ok=True,model_available=state.router.model is not None,agent_online=state.online()));return
            if self.path.startswith('/api/'):
                if not self.gate(self.path.startswith('/api/agent/')): return
                if self.path=='/api/state': self.reply(200,state.snapshot());return
                if self.path=='/api/agent/next':
                    with state.lock: commands=list(state.commands);state.commands.clear()
                    self.reply(200,dict(commands=commands));return
                self.reply(404,dict(error='unknown endpoint'));return
            files={'/':('index.html','text/html; charset=utf-8'),'/app.js':('app.js','application/javascript'),'/style.css':('style.css','text/css')}
            if self.path not in files: self.reply(404,dict(error='not found'));return
            name,mime=files[self.path];self.reply(200,(HERE/'static'/name).read_bytes(),mime)
        def do_POST(self):
            if self.path not in ('/api/control','/api/agent/update','/api/shutdown'): self.reply(404,dict(error='unknown endpoint'));return
            if not self.gate(self.path.startswith('/api/agent/')): return
            if self.path=='/api/shutdown':
                self.reply(200,dict(ok=True));threading.Thread(target=self.server.shutdown,daemon=True).start();return
            try:
                if self.headers.get('Transfer-Encoding'): raise ValueError('chunked input unsupported')
                length=int(self.headers.get('Content-Length','0'))
                if not 0<length<=65536:
                    # Consume the boundary-sized rejected upload so closing the
                    # connection cannot reset a client still sending its body.
                    # Both byte count and elapsed drain time are strictly bounded.
                    remaining=min(max(length,0),65537)
                    deadline=time.monotonic()+.25
                    previous_timeout=self.connection.gettimeout()
                    try:
                        while remaining:
                            timeout=deadline-time.monotonic()
                            if timeout<=0: break
                            self.connection.settimeout(timeout)
                            chunk=self.rfile.read1(min(remaining,8192))
                            if not chunk: break
                            remaining-=len(chunk)
                    except OSError:
                        pass
                    finally:
                        self.connection.settimeout(previous_timeout)
                    self.close_connection=True
                    self.reply(413,dict(error='body must be 1..65536 bytes'));return
                if self.headers.get('Content-Type','').split(';')[0]!='application/json': raise ValueError('JSON content type required')
                self.connection.settimeout(5);data=json.loads(self.rfile.read(length),parse_constant=lambda x: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
                result=state.control(data) if self.path=='/api/control' else state.update(data)
                self.reply(200,result or dict(ok=True))
            except (ValueError,TypeError,KeyError) as e: self.reply(400,dict(error=str(e)))
    server=ThreadingHTTPServer((host,port),Handler);server.daemon_threads=True;server.state=state;return server

def main():
    p=argparse.ArgumentParser();p.add_argument('--host',default='127.0.0.1');p.add_argument('--port',type=int,default=8767);p.add_argument('--model',type=Path,default=HERE/'native-model.json');a=p.parse_args()
    server=make_server(a.host,a.port,a.model,os.environ.get('WINDOWS_STREAM_TOKEN',''),os.environ.get('WINDOWS_AGENT_TOKEN',''));print('Windows streaming service on port',a.port,flush=True)
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()
if __name__=='__main__':main()
