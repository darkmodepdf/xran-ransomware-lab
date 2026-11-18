"""Dependency-free, bounded actor inference shared by fitting, replay and HTTP."""
from collections import Counter, deque
import hashlib
import json
import math
from pathlib import Path
from .windows_events import VERSION

HORIZON=128
OPS=('open','read','write','close','rename','delete','delete_intent','resize','allocation','position','metadata','setinfo','duplicate')
FEATURES=tuple('op_'+op for op in OPS)+('failed','pending','unknown_outcome','file_candidate','unknown_target','unique_targets','unique_write_targets','read_write_overlap','occupancy')

def canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()

class History:
    def __init__(self):
        self.events=deque(); self.seq=0; self.evictions=0; self.identity=None
        self.ops=Counter(); self.outcomes=Counter(); self.kinds=Counter(); self.targets=Counter(); self.reads=Counter(); self.writes=Counter(); self.overlap=0
    def _change(self,e,delta):
        self.ops[e['op']]+=delta; self.outcomes[e['outcome']]+=delta; self.kinds[e['target_kind']]+=delta
        target=e.get('target')
        if target is not None:
            self.targets[target]+=delta
            if not self.targets[target]: del self.targets[target]
            if e['outcome']=='success' and e['target_kind']=='file_candidate' and e['op'] in ('read','write'):
                before=bool(self.reads[target] and self.writes[target]); counts=self.reads if e['op']=='read' else self.writes
                counts[target]+=delta
                if not counts[target]: del counts[target]
                self.overlap+=int(bool(self.reads[target] and self.writes[target]))-int(before)
    def add(self,e):
        validate(e)
        identity=(e['pid'],e['incarnation'])
        if self.identity is not None and identity!=self.identity: raise ValueError('actor PID/incarnation changed')
        if e['seq']!=self.seq+1: raise ValueError('actor sequence gap or duplicate')
        self.identity=identity
        self.seq=e['seq']; self.events.append(e); self._change(e,1)
        if len(self.events)>HORIZON:
            self._change(self.events.popleft(),-1); self.evictions+=1
        return self.vector()
    def vector(self):
        n=max(1,len(self.events))
        return [self.ops[op]/n for op in OPS]+[self.outcomes['failure']/n,self.outcomes['pending']/n,self.outcomes['unknown']/n,self.kinds['file_candidate']/n,self.kinds['unknown']/n,len(self.targets)/n,len(self.writes)/n,self.overlap/n,len(self.events)/HORIZON]

def validate(e):
    if not isinstance(e,dict) or e.get('schema')!=VERSION: raise ValueError('event schema mismatch')
    if not isinstance(e.get('actor'),str) or not 1<=len(e['actor'])<=256: raise ValueError('missing actor identity')
    if type(e.get('pid')) is not int or e['pid']<=0 or not e.get('incarnation'): raise ValueError('missing PID/incarnation')
    if type(e.get('seq')) is not int or e['seq']<1: raise ValueError('invalid sequence')
    if e.get('op') not in OPS or e.get('outcome') not in ('success','failure','pending','unknown') or e.get('target_kind') not in ('file_candidate','directory','nonfile','unknown'): raise ValueError('invalid event categories')
    if e.get('target') is not None and (not isinstance(e['target'],str) or len(e['target'])>256): raise ValueError('invalid target')
    for key in ('requested_bytes','completed_bytes'):
        if e.get(key) is not None and (type(e[key]) is not int or not 0<=e[key]<=2**63-1): raise ValueError('invalid byte count')

class Model:
    def __new__(cls,bundle):
        candidate=json.loads(Path(bundle).read_text(encoding='utf8')) if isinstance(bundle,(str,Path)) else bundle
        if isinstance(candidate,dict) and isinstance(candidate.get('payload'),dict) and candidate['payload'].get('schema') in ('windows-native-forest-v1','windows-native-forest-v2'):
            if candidate['payload']['schema']=='windows-native-forest-v1':
                from .windows_native_v1 import Model as NativeModel
            else:
                from .windows_native import Model as NativeModel
            return NativeModel(candidate)
        return super().__new__(cls)
    def __init__(self,bundle):
        if isinstance(bundle,(str,Path)): bundle=json.loads(Path(bundle).read_text(encoding='utf8'))
        if not isinstance(bundle,dict): raise ValueError('invalid model bundle')
        payload=bundle.get('payload'); digest=bundle.get('sha256')
        if not isinstance(payload,dict) or hashlib.sha256(canonical(payload)).hexdigest()!=digest: raise ValueError('model hash mismatch')
        if payload.get('schema')!='windows-mil-linear-v1' or payload.get('event_schema')!=VERSION or payload.get('features')!=list(FEATURES) or payload.get('horizon')!=HORIZON: raise ValueError('model schema mismatch')
        self.weights=payload['weights']; self.bias=payload['bias']; self.threshold=payload['threshold']; self.payload=payload
        if len(self.weights)!=len(FEATURES) or any(type(x) not in (int,float) or not math.isfinite(x) for x in self.weights+[self.bias,self.threshold]) or not 0<=self.threshold<=1: raise ValueError('nonfinite or invalid model parameters')
    def score(self,x):
        if len(x)!=len(FEATURES) or not all(math.isfinite(v) for v in x): raise ValueError('invalid features')
        z=self.bias+sum(w*v for w,v in zip(self.weights,x))
        return 1/(1+math.exp(-z)) if z>=0 else math.exp(z)/(1+math.exp(z))

class Router:
    def __init__(self,model=None,max_actors=512): self.model=model; self.max_actors=max_actors; self.actors={}; self.rejected=0
    def add(self,event):
        try:
            validate(event); actor=event['actor']
            if actor not in self.actors:
                if len(self.actors)>=self.max_actors: raise ValueError('actor capacity reached; no history silently evicted')
                if event['seq']!=1: raise ValueError('new actor must start at sequence 1')
                self.actors[actor]=self.model.history() if self.model and hasattr(self.model,'history') else History()
            h=self.actors[actor]; x=h.add(event); score=self.model.score(x) if self.model else None
            return dict(actor=actor,pid=event['pid'],seq=h.seq,score=score,alert=score>=self.model.threshold if score is not None else False,window=len(h.events),history_evictions=h.evictions,model_available=self.model is not None,score_available=score is not None,score_unavailable_reason='enriched measured telemetry required' if self.model is not None and score is None else None)
        except (ValueError,KeyError,TypeError): self.rejected+=1; raise
