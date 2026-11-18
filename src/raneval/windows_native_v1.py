"""Measured native behavior features and portable tree inference (stdlib only).

Names, job labels, validity, entropy levels, missingness and failure rates are never
features. Whole-file benign saves and destructive overwrites can be identical in
these measurements; the classifier cannot resolve semantic intent.
"""
from collections import deque
import hashlib
import math
from pathlib import Path
import json
from .windows_stream import validate, canonical

HORIZON = 128
FEATURES = ('read_fraction','write_fraction','resize_fraction','append_fraction',
    'overwrite_fraction','truncate_fraction','growth_fraction','shrink_fraction',
    'mean_write_coverage','max_write_coverage','mean_offset_fraction',
    'mean_size_delta_fraction','mean_changed_fraction','mean_entropy_delta',
    'read_then_write_fraction','resize_then_write_fraction','write_then_resize_fraction',
    'unique_targets','unique_mutated_targets','mutated_target_spread','total_write_coverage',
    'partial_overwrite_fraction','repeat_mutation_fraction')


def measured(e):
    validate(e)
    for key in ('byte_offset','file_size_before','file_size_after','file_offset_after'):
        value=e.get(key)
        if value is not None and (type(value) is not int or not 0<=value<=2**63-1):
            raise ValueError('invalid measured offset/size')
    for key in ('entropy_before','entropy_after','changed_byte_fraction'):
        value=e.get(key)
        if value is not None and (type(value) not in (int,float) or not math.isfinite(value) or not 0<=value<=(1 if key=='changed_byte_fraction' else 8)):
            raise ValueError('invalid content measurement')
    if e['outcome']!='success' or e['target_kind']!='file_candidate':return False
    required=['file_size_before','file_size_after','file_offset_after']
    if e['op'] in ('read','write'):required+=['byte_offset','requested_bytes','completed_bytes']
    if e['op']=='resize':required+=['byte_offset']
    if e['op'] in ('write','resize'):required+=['entropy_before','entropy_after','changed_byte_fraction']
    if e['op'] not in ('open','read','write','resize','close'):return False
    if not e.get('target') or any(e.get(k) is None for k in required):return False
    if e['op'] in ('read','write'):
        if e['completed_bytes']>e['requested_bytes'] or e['file_offset_after']!=e['byte_offset']+e['completed_bytes']:
            raise ValueError('inconsistent completed operation')
        if e['op']=='read' and e['completed_bytes']>0 and e['byte_offset']+e['completed_bytes']>e['file_size_before']:raise ValueError('read exceeds observed size')
        if e['op']=='write' and e['completed_bytes']>0 and e['byte_offset']+e['completed_bytes']>e['file_size_after']:raise ValueError('write exceeds observed size')
    return True


class History:
    def __init__(self):
        self.events=deque();self.seq=0;self.evictions=0;self.identity=None
    def add(self,e):
        complete=measured(e);identity=(e['pid'],e['incarnation'])
        if self.identity is not None and identity!=self.identity:raise ValueError('actor PID/incarnation changed')
        if e['seq']!=self.seq+1:raise ValueError('actor sequence gap or duplicate')
        self.identity=identity;self.seq=e['seq'];self.events.append((dict(e),complete))
        if len(self.events)>HORIZON:self.events.popleft();self.evictions+=1
        return self.vector()
    def vector(self):
        if not self.events or not all(complete for _,complete in self.events):return None
        events=[e for e,_ in self.events];n=len(events);counts=dict.fromkeys(FEATURES,0.)
        targets=set();mutated=set();last={};cover=[];offsets=[];deltas=[];changed=[];entropy=[]
        for e in events:
            op=e['op'];target=e['target'];targets.add(target);previous=last.get(target)
            if op in ('read','write','resize'):counts[op+'_fraction']+=1
            if op in ('write','resize'):
                before=e['file_size_before'];after=e['file_size_after'];offset=e['byte_offset']
                counts['repeat_mutation_fraction']+=target in mutated;mutated.add(target)
                counts['growth_fraction']+=after>before;counts['shrink_fraction']+=after<before
                counts['truncate_fraction']+=op=='resize' and after<before
                deltas.append((after-before)/max(1,before,after));changed.append(e['changed_byte_fraction'])
                entropy.append((e['entropy_after']-e['entropy_before'])/8)
                if op=='write':
                    completed=e['completed_bytes'];coverage=min(completed,max(0,before-offset))/max(1,before)
                    cover.append(coverage);offsets.append(min(1,offset/max(1,before)))
                    counts['append_fraction']+=offset>=before and completed>0
                    counts['overwrite_fraction']+=offset<before and completed>0
                    counts['partial_overwrite_fraction']+=offset<before and 0<coverage<1
                    counts['read_then_write_fraction']+=previous=='read'
                    counts['resize_then_write_fraction']+=previous=='resize'
                else:counts['write_then_resize_fraction']+=previous=='write'
            last[target]=op
        for key in FEATURES:counts[key]/=n
        mean=lambda values:sum(values)/max(1,len(values))
        counts.update(mean_write_coverage=mean(cover),max_write_coverage=max(cover,default=0),mean_offset_fraction=mean(offsets),mean_size_delta_fraction=mean(deltas),mean_changed_fraction=mean(changed),mean_entropy_delta=mean(entropy),unique_targets=len(targets)/n,unique_mutated_targets=len(mutated)/n,mutated_target_spread=len(mutated)/max(1,len(targets)),total_write_coverage=sum(cover)/n)
        return [counts[k] for k in FEATURES]


class Model:
    def __init__(self,bundle):
        if isinstance(bundle,(str,Path)):bundle=json.loads(Path(bundle).read_text(encoding='utf8'))
        payload=bundle.get('payload')
        if not isinstance(payload,dict) or hashlib.sha256(canonical(payload)).hexdigest()!=bundle.get('sha256'):raise ValueError('model hash mismatch')
        if payload.get('schema')!='windows-native-forest-v1' or payload.get('event_schema')!='windows-event-v1' or payload.get('features')!=list(FEATURES) or payload.get('horizon')!=HORIZON:raise ValueError('native model schema mismatch')
        self.payload=payload;self.threshold=payload['threshold'];self.trees=payload['trees']
        if type(self.threshold) not in (float,int) or not math.isfinite(self.threshold) or not 0<=self.threshold<=1:raise ValueError('invalid threshold')
        if not isinstance(self.trees,list) or not 1<=len(self.trees)<=256:raise ValueError('invalid trees')
        for tree in self.trees:
            if not isinstance(tree,list) or not 1<=len(tree)<=8192:raise ValueError('invalid tree')
            for i,node in enumerate(tree):
                if not isinstance(node,list) or len(node)!=5:raise ValueError('invalid node')
                feature,cut,left,right,value=node
                if type(feature) is not int or not -1<=feature<len(FEATURES) or any(type(v) not in (float,int) or not math.isfinite(v) for v in (cut,value)) or not 0<=value<=1:raise ValueError('invalid tree parameter')
                if feature>=0 and (type(left) is not int or type(right) is not int or not i<left<len(tree) or not i<right<len(tree)):raise ValueError('invalid tree links')
    def history(self):return History()
    def score(self,x):
        if x is None:return None
        if len(x)!=len(FEATURES) or not all(math.isfinite(v) for v in x):raise ValueError('invalid native features')
        total=0.
        # sklearn's trees consume float32; round inputs exactly, without numpy.
        import struct
        values=[struct.unpack('f',struct.pack('f',v))[0] for v in x]
        for tree in self.trees:
            i=0
            while tree[i][0]>=0:
                feature,cut,left,right,_=tree[i];i=left if values[feature]<=cut else right
            total+=tree[i][4]
        return total/len(self.trees)
