"""Fit a capture-level maximum-instance baseline after the full streaming audit."""
import os
os.environ.setdefault('OPENBLAS_NUM_THREADS','1')
import argparse
from collections import Counter
import gzip
import hashlib
import json
import math
from pathlib import Path
import random
import numpy as np
import torch
from sklearn.metrics import roc_auc_score
from raneval.windows_stream import History,Model,FEATURES,HORIZON,canonical
from raneval.windows_events import VERSION

def groups(reports):
    parents=list(range(len(reports)))
    def root(i):
        while parents[i]!=i: parents[i]=parents[parents[i]]; i=parents[i]
        return i
    seen={}
    for i,r in enumerate(reports):
        for field in ('raw_sha256','sample_sha256','sequence_sha256'):
            value=r.get(field)
            if value:
                key=(field,value)
                if key in seen: parents[root(i)]=root(seen[key])
                else: seen[key]=i
    out={}
    for i,r in enumerate(reports): out.setdefault(root(i),[]).append(r)
    return list(out.values())

def assign(reports,seed):
    assignments=[]; conflicts=[]
    for label in ('benign','ransomware'):
        eligible=[]
        for group in groups(reports):
            labels={r['label'] for r in group}
            if len(labels)>1:
                if group[0]['raw_sha256'] not in conflicts: conflicts.append(group[0]['raw_sha256'])
            elif group[0]['label']==label: eligible.append(group)
        random.Random(str(seed)+label).shuffle(eligible)
        n=len(eligible); boundaries=(int(n*.55),int(n*.7),int(n*.85),n); start=0
        for role,end in zip(('train','tune','calibrate','test'),boundaries):
            for g in eligible[start:end]:
                gid=min(r['raw_sha256'] for r in g)
                for r in g: assignments.append(dict(r,role=role,group_id=gid))
            start=end
    return assignments,conflicts

def bag(path):
    # CAPE projection is process-contiguous. Release completed actors immediately.
    current=None; h=None; rows=[]; n=0; last=None; evictions=0
    with gzip.open(path,'rt',encoding='utf8') as f:
        for line in f:
            e=json.loads(line)
            if e['actor']!=current:
                if h: evictions+=h.evictions
                if h and last is not None and h.seq%16: rows.append(last)
                current=e['actor']; h=History()
            last=h.add(e); n+=1
            if h.seq==1 or h.seq%16==0: rows.append(last)
    if h and last is not None and h.seq%16: rows.append(last)
    if h: evictions+=h.evictions
    return np.asarray(rows,dtype=np.float64),n,evictions

def metrics(y,s,threshold):
    pred=np.asarray(s)>=threshold; y=np.asarray(y)
    return dict(sessions=len(y),benign=int(sum(y==0)),ransomware=int(sum(y==1)),tp=int(sum(pred&(y==1))),fp=int(sum(pred&(y==0))),tn=int(sum(~pred&(y==0))),fn=int(sum(~pred&(y==1))),auroc=float(roc_auc_score(y,s)) if len(set(y))==2 else None)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--data',type=Path,default=Path('data/processed/en2025-streaming'));p.add_argument('--output',type=Path,default=Path('demo/windows_streaming/model.json'));p.add_argument('--seed',type=int,default=20261117);a=p.parse_args()
    audit_path=a.data/'audit.json';audit=json.loads(audit_path.read_text(encoding='utf8'))
    if audit['selected']!=360 or audit['dispositions']!={'projected':360}: raise ValueError('full 360-report audit required; errors need explicit resolution')
    assignments,conflicts=assign(audit['reports'],a.seed)
    manifest=[{k:r[k] for k in ('raw_sha256','sample_sha256','sequence_sha256','label','role','group_id')} for r in assignments]
    a.output.parent.mkdir(parents=True,exist_ok=True)
    (a.output.parent/'split.json').write_text(json.dumps(dict(seed=a.seed,reports=manifest,excluded_conflicting_groups=conflicts),indent=2),encoding='utf8')
    bags=[]; event_counts=[]; eviction_counts=[]
    for i,r in enumerate(assignments):
        x,n,evictions=bag(a.data/r['events']); bags.append(x);event_counts.append(n);eviction_counts.append(evictions)
        if (i+1)%30==0: print('features',i+1,flush=True)
    torch.set_num_threads(1);torch.manual_seed(a.seed)
    train=[i for i,r in enumerate(assignments) if r['role']=='train']; tune=[i for i,r in enumerate(assignments) if r['role']=='tune']
    X=torch.tensor(np.concatenate([bags[i] for i in train]),dtype=torch.float64)
    sizes=[len(bags[i]) for i in train]; ids=torch.repeat_interleave(torch.arange(len(train)),torch.tensor(sizes));Y=torch.tensor([assignments[i]['label']=='ransomware' for i in train],dtype=torch.float64)
    candidates=[]; best=None
    for decay in (.001,.01,.1):
        torch.manual_seed(a.seed);w=torch.nn.Parameter(torch.randn(len(FEATURES),dtype=torch.float64)*.01);b=torch.nn.Parameter(torch.zeros((),dtype=torch.float64));opt=torch.optim.Adam([w,b],lr=.04)
        for epoch in range(160):
            opt.zero_grad();z=X@w+b; pooled=torch.full((len(train),),-float('inf'),dtype=torch.float64).scatter_reduce(0,ids,z,reduce='amax',include_self=True)
            loss=torch.nn.functional.binary_cross_entropy_with_logits(pooled,Y)+decay*(w*w).sum();loss.backward();opt.step()
        weights=w.detach().numpy().tolist();bias=float(b.detach());scores=[float(1/(1+np.exp(-np.max(bags[i]@np.array(weights)+bias)))) for i in tune];y=[int(assignments[i]['label']=='ransomware') for i in tune];auc=float(roc_auc_score(y,scores));candidates.append(dict(weight_decay=decay,tune_sampled_prefix_auroc=auc))
        if best is None or auc>best[0]: best=(auc,weights,bias,decay)
    _,weights,bias,decay=best
    payload=dict(schema='windows-mil-linear-v1',event_schema=VERSION,features=list(FEATURES),horizon=HORIZON,weights=weights,bias=bias,threshold=.5,audit_sha256=hashlib.sha256(audit_path.read_bytes()).hexdigest(),seed=a.seed,training='Capture-level max-instance logistic loss; snapshots at actor first/every16/final event; no prefix labels',weight_decay=decay)
    model=Model(dict(payload=payload,sha256=hashlib.sha256(canonical(payload)).hexdigest()))
    # Evaluate ALL observed prefixes for tune/calibration/test through shipped runtime, not sampled training windows.
    session_scores=[]; parity=0.0
    for i,r in enumerate(assignments):
        current=None;h=None;maximum=0.;
        if r['role']=='train': session_scores.append(max(model.score(x) for x in bags[i]));continue
        with gzip.open(a.data/r['events'],'rt',encoding='utf8') as f:
            for line in f:
                e=json.loads(line)
                if current!=e['actor']: current=e['actor'];h=History()
                x=h.add(e);score=model.score(x);maximum=max(maximum,score)
        session_scores.append(maximum)
        ref=max(model.score(x) for x in bags[i]); npref=float(1/(1+np.exp(-np.max(bags[i]@np.array(weights)+bias))));parity=max(parity,abs(ref-npref))
    calibration=[session_scores[i] for i,r in enumerate(assignments) if r['role']=='calibrate' and r['label']=='benign']
    if not calibration: raise ValueError('no benign calibration sessions')
    payload['threshold']=math.nextafter(max(calibration),1.0)
    payload['calibration']=dict(method='strictly above maximum benign calibration session score',benign_sessions=len(calibration),maximum=max(calibration))
    bundle=dict(payload=payload,sha256=hashlib.sha256(canonical(payload)).hexdigest());a.output.write_text(json.dumps(bundle,indent=2),encoding='utf8');reloaded=Model(a.output)
    if any(reloaded.score(x)!=model.score(x) for x in bags[0]): raise AssertionError('reload parity')
    evaluation=dict(candidates=candidates,selected_weight_decay=decay,threshold=payload['threshold'],runtime_numeric_max_error=parity,assignments=dict(Counter(r['role'] for r in assignments)),events_processed=sum(event_counts),sampled_training_instances=sum(len(bags[i]) for i in train),window_horizon=HORIZON,history_evictions=sum(eviction_counts),conflicting_groups=conflicts,metrics={})
    for role in ('tune','calibrate','test'):
        indices=[i for i,r in enumerate(assignments) if r['role']==role];evaluation['metrics'][role]=metrics([int(assignments[i]['label']=='ransomware') for i in indices],[session_scores[i] for i in indices],payload['threshold'])
    evaluation['limitations']=['Development subset only; test is locked within already inspected development captures, not an external holdout.','Exact raw/sample/full API sequence groups are transitive and disjoint; family/near-duplicate/source independence is unverified.','Capture labels supervise a maximum instance score, never every ransomware prefix or child.','One linear baseline, weak labels, small calibration cohort, no recall guarantees.','CAPE vs native fixture collector/domain shift is unmeasured. Actual invalid files may receive no model alert.','Paths, names, scenario, oracle, bytes and timestamps excluded from learned inputs. Target identities used only as bounded equality counts.']
    payload['evaluation']=evaluation['metrics']['test']
    bundle=dict(payload=payload,sha256=hashlib.sha256(canonical(payload)).hexdigest())
    a.output.write_text(json.dumps(bundle,indent=2),encoding='utf8')
    (a.output.parent/'evaluation.json').write_text(json.dumps(evaluation,indent=2),encoding='utf8')
    report=Path('output/research/windows-streaming-evaluation.md');report.write_text('# Windows streaming baseline\n\n```json\n'+json.dumps(evaluation,indent=2)+'\n```\n',encoding='utf8'); print(json.dumps(evaluation,indent=2))

if __name__=='__main__': main()
