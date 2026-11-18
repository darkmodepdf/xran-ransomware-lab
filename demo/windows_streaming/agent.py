"""Native Windows generated-fixture supervisor. No arbitrary commands or host paths."""
import argparse
import hashlib
import json
import os
import math
from pathlib import Path
import queue
import random
import secrets
import subprocess
import sys
import tempfile
import threading
import time
from urllib.request import Request,urlopen
import uuid

NAMES=tuple(f'fixture-{i}.jsonl' for i in range(6))
FIXTURE=(json.dumps({'format':'windows-stream-fixture-v1','payload':'generated documentation'})+'\n').encode()
BINARY_MAGIC=b'windows-stream-binary-fixture-v1\n'
VARIANTS={'benign':('append','save','rotate','copy'),'destructive':('truncate','overwrite','sparse')}
PROFILES=('mixed','compact','repetitive','structured')

def campaign_config(kind,value=None):
    """Internal experiment knobs: no filenames, paths, commands or payload input."""
    if kind not in VARIANTS:raise ValueError('invalid worker kind')
    if value is None:return None
    if not isinstance(value,dict) or set(value)-{'variant','seed','cycles','delay','warmup','profile'}:raise ValueError('invalid campaign fields')
    result=dict(variant=VARIANTS[kind][0],seed=0,cycles=4,delay=0.,warmup=0,profile='mixed')
    result.update(value)
    if result['variant'] not in VARIANTS[kind]:raise ValueError('invalid campaign variant')
    if result['profile'] not in PROFILES:raise ValueError('invalid campaign profile')
    if type(result['seed']) is not int or not 0<=result['seed']<2**31:raise ValueError('invalid campaign seed')
    if type(result['cycles']) is not int or not 1<=result['cycles']<=20:raise ValueError('invalid campaign cycles')
    if type(result['warmup']) is not int or not 0<=result['warmup']<result['cycles']:raise ValueError('invalid campaign warmup')
    if type(result['delay']) not in (int,float) or not math.isfinite(result['delay']) or not 0<=result['delay']<=.1:raise ValueError('invalid campaign delay')
    return result

def fixture_bytes(rng,profile='mixed'):
    # The same generator initializes either class. Payload size/content are not labels.
    if profile not in PROFILES:raise ValueError('invalid fixture profile')
    if profile=='compact':return FIXTURE
    if profile=='repetitive':
        payload=rng.choice(('a','0','generated documentation '))*rng.randint(8,24)
        return (json.dumps({'format':'windows-stream-fixture-v1','payload':payload})+'\n').encode()
    if profile=='structured':
        payload={'rows':list(range(rng.randint(8,96))),'version':rng.randrange(5),'title':'generated documentation'}
        return (json.dumps({'format':'windows-stream-fixture-v1','payload':payload})+'\n').encode()
    if rng.randrange(3)==0:
        payload=bytes(rng.randrange(256) for _ in range(rng.randint(384,3072)))
        return BINARY_MAGIC+len(payload).to_bytes(4,'little')+hashlib.sha256(payload).digest()+payload
    alphabet='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 '
    payload=''.join(rng.choice(alphabet) for _ in range(rng.randint(96,768)))
    return (json.dumps({'format':'windows-stream-fixture-v1','payload':payload})+'\n').encode()

def replacement_bytes(rng,size,profile):
    """Harmless replacement data; the model never receives literal content."""
    if profile=='compact':
        if size==25:return b'INVALID GENERATED FIXTURE\n'
        pattern=rng.choice((b'INVALID GENERATED FIXTURE\n',b'x',b'generated alteration '))
    elif profile=='repetitive':pattern=rng.choice((b'A',b'0',b'unchanged-shaped data '))
    elif profile=='structured':pattern=b'{"rows":[0,1,2,3],"payload":"generated documentation"}\n'
    else:return bytes(rng.randrange(256) for _ in range(size))
    return (pattern*((size+len(pattern)-1)//len(pattern)))[:size]

def entropy(content):
    if not content:return 0.
    counts={}
    for b in content:counts[b]=counts.get(b,0)+1
    return -sum((n/len(content))*math.log2(n/len(content)) for n in counts.values())

def digest(content):return hashlib.sha256(content).hexdigest()
def valid(content):
    if content.startswith(BINARY_MAGIC):
        start=len(BINARY_MAGIC)
        if len(content)<start+36:return False
        size=int.from_bytes(content[start:start+4],'little');expected=content[start+4:start+36];payload=content[start+36:]
        return len(payload)==size and hashlib.sha256(payload).digest()==expected
    try:
        lines=content.decode('utf8').splitlines()
        return bool(lines) and all(isinstance(v,dict) and v.get('format')=='windows-stream-fixture-v1' for v in map(json.loads,lines))
    except (ValueError,UnicodeError):return False

def owned_root(root,job,marker):
    expected=Path(tempfile.gettempdir()).resolve()/('windows-stream-'+job)
    if root.resolve()!=expected or root.is_symlink() or not root.is_dir() or (root/'.owner').read_text()!=marker: raise ValueError('invalid owned fixture workspace')
    return expected

def evidence(root,job,marker,baseline,actor):
    owned_root(root,job,marker);out=[]
    for name in NAMES:
        path=root/name
        if path.is_symlink() or not path.is_file() or path.stat().st_size>16384:raise ValueError('fixture absent, linked or oversized')
        content=path.read_bytes();sha=digest(content)
        out.append(dict(job=job,file=name,sha256=sha,baseline_sha256=baseline[name],valid=valid(content),changed=sha!=baseline[name],actor=actor,bytes=len(content)))
    return out

def cleanup(root,job,marker):
    owned_root(root,job,marker)
    # Fixed inventory only. Unexpected files or links block cleanup, never recurse.
    allowed=set(NAMES)|{'.owner'}
    actual=list(root.iterdir())
    if any(p.name not in allowed or p.is_symlink() or not p.is_file() for p in actual):raise ValueError('unexpected workspace entry; cleanup refused')
    for p in actual:p.unlink()
    root.rmdir()

def worker(job,kind,campaign=None):
    if os.name!='nt':raise RuntimeError('workers require native Windows')
    marker=os.environ.pop('WINDOWS_WORKER_MARKER','');root=Path.cwd();owned_root(root,job,marker)
    campaign=campaign_config(kind,campaign);rng=random.Random(campaign['seed']) if campaign else None
    seq=0
    def emit(op,name,completed=None,requested=None,offset=None,before=None,after=None,offset_after=None,old=None,new=None):
        nonlocal seq
        seq+=1
        measured=dict(op=op,file=name,completed_bytes=completed,requested_bytes=requested,byte_offset=offset,file_size_before=before,file_size_after=after,file_offset_after=offset_after,seq=seq,thread=threading.get_native_id())
        if old is not None and new is not None:
            measured.update(entropy_before=entropy(old),entropy_after=entropy(new),changed_byte_fraction=(sum(a!=b for a,b in zip(old,new))+abs(len(old)-len(new)))/max(1,len(old),len(new)))
        print(json.dumps(measured),flush=True)
        if sys.stdin.readline().strip()!='ack': raise RuntimeError('supervisor disconnected')
    def resize(f,name,size):
        before=os.fstat(f.fileno()).st_size;offset=f.tell();old=(root/name).read_bytes()
        f.truncate(size);f.flush();os.fsync(f.fileno())
        after=os.fstat(f.fileno()).st_size;new=(root/name).read_bytes()
        emit('resize',name,requested=None,offset=offset,before=before,after=after,offset_after=f.tell(),old=old,new=new)
    def write(f,name,content):
        before=os.fstat(f.fileno()).st_size;offset=f.tell();old=(root/name).read_bytes()
        if offset+len(content)>16384:raise ValueError('bounded fixture write exceeded')
        written=f.write(content);f.flush();os.fsync(f.fileno())
        after=os.fstat(f.fileno()).st_size;new=(root/name).read_bytes()
        emit('write',name,written,len(content),offset,before,after,f.tell(),old,new)
    for cycle in range(campaign['cycles'] if campaign else 12):
        for name in NAMES:
            path=root/name
            if path.is_symlink() or path.stat().st_size>16384:raise ValueError('invalid fixture')
            with path.open('r+b') as f:
                size=os.fstat(f.fileno()).st_size;emit('open',name,before=size,after=size,offset_after=f.tell())
                offset=f.tell();payload=f.read(16384);emit('read',name,len(payload),16384,offset,size,os.fstat(f.fileno()).st_size,f.tell())
                if campaign:
                    profile=campaign['profile']
                    variant=campaign['variant']
                    if kind=='destructive' and cycle<campaign['warmup']:variant='append'
                    if variant=='append':
                        # Binary documents have no append grammar; a legitimate save
                        # rewrites their checksummed envelope instead.
                        if payload.startswith(BINARY_MAGIC):f.seek(0);write(f,name,payload)
                        else:f.seek(0,2);write(f,name,FIXTURE if profile=='mixed' else fixture_bytes(rng,profile))
                    elif variant in ('save','copy'):
                        # Normal saves can overwrite the entire file, a deliberate hard negative.
                        content=fixture_bytes(rng,profile) if variant=='save' else payload
                        f.seek(0);write(f,name,content)
                        if len(content)<size:resize(f,name,len(content))
                    elif variant=='rotate':
                        f.seek(0);resize(f,name,0);write(f,name,fixture_bytes(rng,profile))
                    elif variant=='truncate':
                        f.seek(0);resize(f,name,0 if profile=='compact' else rng.randint(0,max(0,size//3)));f.seek(0)
                        amount=(25 if cycle%3==0 else rng.choice((1,8,25,48))) if profile=='compact' else rng.randint(32,512)
                        write(f,name,replacement_bytes(rng,amount,profile))
                    elif variant=='overwrite':
                        f.seek(0);write(f,name,replacement_bytes(rng,size,profile))
                    elif variant=='sparse':
                        content=replacement_bytes(rng,max(16,size//3),profile)
                        # A literal control byte breaks a JSON document even when
                        # a sparse overwrite lands inside a string; it also breaks
                        # the independently verified binary checksum envelope.
                        content=b'\0'+content[1:]
                        f.seek(rng.randrange(max(1,size//2)));write(f,name,content)
                elif kind=='benign':f.seek(0,2);write(f,name,FIXTURE)
                else:
                    f.seek(0);resize(f,name,0);write(f,name,b'INVALID GENERATED FIXTURE\n')
                final_size=os.fstat(f.fileno()).st_size;final_offset=f.tell()
            emit('close',name,before=final_size,after=final_size,offset_after=final_offset)
            time.sleep(campaign['delay'] if campaign else .06)
    return 0

class Agent:
    def __init__(self,url,token):
        if url!='http://127.0.0.1:8767':raise ValueError('agent connects only to fixed localhost port 8767')
        if len(token)<32:raise ValueError('agent token required')
        self.url=url;self.token=token;self.id=uuid.uuid4().hex;self.jobs={};self.events=queue.Queue(maxsize=1024);self.closed=False;self.errors=[]
    def request(self,path,data=None):
        body=json.dumps(data).encode() if data is not None else None
        req=Request(self.url+path,data=body,headers={'Authorization':'Bearer '+self.token,'Content-Type':'application/json'})
        with urlopen(req,timeout=5) as r:return json.load(r)
    def update(self,**data):return self.request('/api/agent/update',dict(agent_id=self.id,**data))
    def read(self,job,process):
        try:
            for line in process.stdout:
                if len(line)>4096:raise ValueError('worker output line too large')
                self.events.put((job,json.loads(line)),timeout=3)
        except Exception as e:self.events.put((job,{'error':str(e)}),timeout=3)
        finally:self.events.put((job,None),timeout=3)
    def start(self,command):
        job=command['job'];kind=command['kind']
        if kind not in ('benign','destructive') or len(job)!=32 or any(c not in '0123456789abcdef' for c in job):raise ValueError('invalid allowlisted job')
        if len(self.jobs)>=4 or job in self.jobs:raise ValueError('worker capacity or duplicate job')
        campaign=campaign_config(kind,command.get('campaign'))
        root=Path(tempfile.gettempdir()).resolve()/('windows-stream-'+job);root.mkdir();marker=secrets.token_hex(32);(root/'.owner').write_text(marker)
        try:
            rng=random.Random(campaign['seed']) if campaign else None
            initial={name:fixture_bytes(rng,campaign['profile']) if campaign else FIXTURE for name in NAMES}
            for name in NAMES:(root/name).write_bytes(initial[name])
            baseline={name:digest(content) for name,content in initial.items()};born=time.time_ns();env=os.environ.copy();env['WINDOWS_WORKER_MARKER']=marker
            if campaign is not None:env['WINDOWS_WORKER_CAMPAIGN']=json.dumps(campaign)
            else:env.pop('WINDOWS_WORKER_CAMPAIGN',None)
            # Worker receives its marker, not service credentials.
            env.pop('WINDOWS_STREAM_TOKEN',None);env.pop('WINDOWS_AGENT_TOKEN',None)
            process=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'--worker','--job',job,'--kind',kind],cwd=root,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding='utf8',creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        except Exception:
            cleanup(root,job,marker)
            raise
        actor=f'native:{job}:{process.pid}:{born}'
        self.jobs[job]=dict(process=process,root=root,marker=marker,baseline=baseline,actor=actor,born=str(born),started=time.monotonic(),seq=0,stopping=False)
        threading.Thread(target=self.read,args=(job,process),daemon=True).start();self.update(job_status=dict(job=job,status='running'),evidence=evidence(root,job,marker,baseline,actor))
    def stop(self,job):
        if job not in self.jobs:return
        item=self.jobs[job];item['stopping']=True
        if item['process'].poll() is None:item['process'].terminate()
    def consume(self,job,payload):
        if job not in self.jobs:return
        item=self.jobs[job];process=item['process']
        if payload is None:
            process.wait(timeout=3);err=process.stderr.read(2048)
            self.update(evidence=evidence(item['root'],job,item['marker'],item['baseline'],item['actor']),job_status=dict(job=job,status='stopped' if item['stopping'] else ('completed' if process.returncode==0 else 'failed')),**({'error':err} if err else {}))
            process.stdin.close();process.stdout.close();process.stderr.close();cleanup(item['root'],job,item['marker']);del self.jobs[job];return
        if 'error' in payload:raise ValueError('worker collector: '+payload['error'])
        if payload.get('file') not in NAMES or payload.get('op') not in ('open','read','write','close','resize') or payload.get('seq')!=item['seq']+1:raise ValueError('worker event identity/order mismatch')
        item['seq']=payload['seq'];e=dict(schema='windows-event-v1',actor=item['actor'],pid=process.pid,parent_pid=os.getpid(),incarnation=item['born'],thread=payload['thread'],seq=payload['seq'],observed_index=payload['seq'],timestamp=time.time(),api='NativeFixture'+payload['op'].title(),op=payload['op'],outcome='success',target=digest((job+':'+payload['file']).encode()),target_kind='file_candidate',repeated=0,file_information_class=None,job=job)
        for key in ('requested_bytes','completed_bytes','byte_offset','file_size_before','file_size_after','file_offset_after','entropy_before','entropy_after','changed_byte_fraction'):e[key]=payload.get(key)
        self.update(event=e,evidence=evidence(item['root'],job,item['marker'],item['baseline'],item['actor']))
        if process.poll() is None: process.stdin.write('ack\n');process.stdin.flush()
    def run(self):
        if os.name!='nt':raise RuntimeError('native agent requires Windows')
        last=0
        try:
            while True:
                now=time.monotonic()
                if now-last>.5:
                    self.update()
                    for cmd in self.request('/api/agent/next')['commands']:
                        try:
                            if cmd['action']=='start':self.start(cmd)
                            elif cmd['action']=='stop':self.stop(cmd['job'])
                            else:raise ValueError('unknown agent command')
                        except Exception as e:self.update(error=str(e),job_status=dict(job=cmd['job'],status='failed'))
                    last=now
                for job,item in list(self.jobs.items()):
                    if now-item['started']>30:self.stop(job)
                try:job,payload=self.events.get(timeout=.05)
                except queue.Empty:continue
                try:self.consume(job,payload)
                except Exception as e:self.errors.append(str(e));self.update(error=str(e));self.stop(job)
        finally:self.close()
    def close(self):
        if self.closed:return
        self.closed=True
        for job,item in list(self.jobs.items()):
            self.stop(job)
            try:
                item['process'].wait(timeout=5);cleanup(item['root'],job,item['marker'])
            except Exception as e:self.errors.append(str(e))
        self.jobs.clear()

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--worker',action='store_true');p.add_argument('--job');p.add_argument('--kind',choices=('benign','destructive'));a=p.parse_args()
    if a.worker:
        if not a.job or not a.kind:p.error('internal worker job/kind required')
        campaign=json.loads(os.environ.pop('WINDOWS_WORKER_CAMPAIGN','null'))
        worker(a.job,a.kind,campaign)
    else:
        try:Agent('http://127.0.0.1:8767',os.environ.get('WINDOWS_AGENT_TOKEN','')).run()
        except KeyboardInterrupt:pass
if __name__=='__main__':main()
