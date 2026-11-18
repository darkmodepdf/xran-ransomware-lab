"""Collect measured owned Windows campaigns, freeze partitions, fit/export/evaluate.

Run with PYTHONPATH=src. Runtime inference never imports sklearn or numpy.
The manifest is written before collection; training never opens test until the
bundle and threshold have been frozen. All labels/evidence stay outside features.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import queue
import random
import time
import uuid

from raneval.windows_stream import Model,Router,canonical
from raneval.windows_native import History,FEATURES,HORIZON
from raneval.windows_native_v1 import History as HistoryV1,FEATURES as FEATURES_V1
ROOT=Path(__file__).resolve().parents[1]


def write(path,value):
    Path(path).parent.mkdir(parents=True,exist_ok=True)
    Path(path).write_text(json.dumps(value,indent=2,allow_nan=False),encoding='utf8')


def manifest_v1():
    rows=[]
    variants={'benign':['append','save','rotate'],'destructive':['truncate','overwrite']}
    for role,count in [('train',8),('tune',4),('calibrate',10),('test',6)]:
        for kind,names in variants.items():
            if role=='calibrate' and kind!='benign':continue
            names=names+(['copy'] if kind=='benign' else ['sparse']) if role=='test' else names
            for variant in names:
                for repeat in range(count):
                    seed=100000*(['train','tune','calibrate','test'].index(role)+1)+1000*(['append','save','rotate','copy','truncate','overwrite','sparse'].index(variant)+1)+repeat
                    rng=random.Random(seed)
                    rows.append(dict(id=f'{role}-{kind}-{variant}-{repeat}',role=role,kind=kind,campaign=dict(variant=variant,seed=seed,cycles=rng.randint(3,5),warmup=1 if kind=='destructive' and repeat%2 else 0,delay=rng.choice([0,.001,.002]))))
    return dict(version=1,split_unit='whole campaign and one PID incarnation',seed=20261118,calibration_budget=0,holdout_variants=['copy','sparse'],limitations='Variant holdouts share worker templates and fixture generators; they are not independent malware families.',campaigns=rows)



def manifest(experiment='v1'):
    if experiment=='v1':return manifest_v1()
    rows=[]
    variants={'benign':['append','save','rotate','copy'],'destructive':['truncate','overwrite','sparse']}
    profiles=['mixed','compact','repetitive']
    for role,count in [('train',4),('tune',2),('calibrate',4),('test',2)]:
        for kind,names in variants.items():
            if role=='calibrate' and kind!='benign':continue
            for variant in names:
                for profile in profiles+(['structured'] if role=='test' else []):
                    for repeat in range(count):
                        seed=2000000+100000*(['train','tune','calibrate','test'].index(role)+1)+10000*(['append','save','rotate','copy','truncate','overwrite','sparse'].index(variant)+1)+100*(['mixed','compact','repetitive','structured'].index(profile)+1)+repeat
                        rng=random.Random(seed)
                        warmup=rng.choice([1,2]) if kind=='destructive' and repeat%2 else 0
                        rows.append(dict(id=f'{role}-{kind}-{variant}-{profile}-{repeat}',role=role,kind=kind,campaign=dict(variant=variant,profile=profile,seed=seed,cycles=rng.randint(4,7),warmup=warmup,delay=rng.choice([0,.001,.002]))))
    candidates=[dict(depth=depth,min_samples_leaf=leaf) for depth,leaf in [(2,4),(3,4),(3,8),(4,4),(5,4),(5,8),(7,4),(7,8),(9,4),(5,20)]]
    return dict(version=2,experiment='v2',split_unit='whole campaign and one PID incarnation',seed=2026111802,calibration_budget=0,holdout_variants=[],holdout_profiles=['structured'],model_candidates=candidates,trees_per_candidate=32,selection_policy='Maximize onset-qualified tuning campaign recall at a cutoff immediately above the largest benign tuning session maximum; tie-break fewer false alerts, then smaller mean onset-to-alert event delay among detected tuning campaigns, then fewer tree nodes.',cutoff_policy='After selecting one estimator, use the next representable float above the largest benign calibration session maximum. Clip at1 only at the score ceiling, explicitly reporting an unattainable zero-alert budget. Never adjust after opening test.',retired_evidence='v1 test and HTTP default-worker failures are diagnostic development evidence, not untouched evidence for v2.',limitations='All operation variants and three content profiles occur in development. Structured profile and fresh seeds are held out, but share worker templates and fixture grammars; no independent malware-family or production generalization claim.',campaigns=rows)


def collect(out,experiment='v1'):
    out=Path(out);out.mkdir(parents=True,exist_ok=True);mp=out/'manifest.json'
    if mp.exists():raise ValueError('refusing to overwrite existing frozen manifest')
    spec=manifest(experiment);write(mp,spec)
    print('manifest frozen',hashlib.sha256(mp.read_bytes()).hexdigest(),'campaigns',len(spec['campaigns']),flush=True)
    for source,name in [(ROOT/'demo/windows_streaming/agent.py','agent.py'),(ROOT/'src/raneval/windows_native.py','windows_native.py'),(Path(__file__),'train_windows_native.py')]:
        destination=out/'source'/name;destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(source.read_bytes())
    module_spec=importlib.util.spec_from_file_location('native_agent',ROOT/'demo/windows_streaming/agent.py');agent_module=importlib.util.module_from_spec(module_spec);module_spec.loader.exec_module(agent_module)
    class Capture(agent_module.Agent):
        def __init__(self):super().__init__('http://127.0.0.1:8767','a'*32);self.records=[]
        def update(self,**data):self.records.append(data)
    summaries=[]
    for row in spec['campaigns']:
        a=Capture();job=uuid.uuid4().hex;start=time.perf_counter();root=None
        try:
            a.start(dict(job=job,kind=row['kind'],campaign=row['campaign']));root=a.jobs[job]['root']
            deadline=time.monotonic()+45
            while a.jobs:
                if time.monotonic()>deadline:raise TimeoutError('campaign deadline')
                key,payload=a.events.get(timeout=10);a.consume(key,payload)
            records=a.records
            if any(r.get('job_status',{}).get('status')=='failed' or r.get('error') for r in records):raise RuntimeError('native campaign failed')
            if root.exists():raise AssertionError('fixture root not cleaned')
            with gzip.open(out/(row['id']+'.jsonl.gz'),'wt',encoding='utf8') as f:
                for record in records:f.write(json.dumps(record)+'\n')
            summaries.append(dict(id=row['id'],events=sum('event' in r for r in records),seconds=time.perf_counter()-start,cleaned=True))
        finally:a.close()
        if len(summaries)%10==0:print('collected',len(summaries),'/',len(spec['campaigns']),flush=True)
    write(out/'collection.json',dict(campaigns=summaries,total_seconds=sum(s['seconds'] for s in summaries)))


def load(out,row):
    records=[json.loads(line) for line in gzip.open(Path(out)/(row['id']+'.jsonl.gz'),'rt',encoding='utf8')]
    events=[];evidence=[];onset=None;invalid={}
    for record in records:
        if 'event' not in record:continue
        e=record['event'];events.append(e);ev=record['evidence'];bad=sum(not f['valid'] for f in ev);invalid[e['seq']]=bad
        # Validity is observed independently after each real operation, outside model inputs.
        if row['kind']=='destructive' and onset is None and bad:onset=e['seq']
        evidence.append(ev)
    h=History() if 'profile' in row['campaign'] else HistoryV1();vectors=[h.add(e) for e in events]
    if any(x is None for x in vectors):raise AssertionError('incomplete collected measurement')
    return dict(row=row,events=events,vectors=vectors,onset=onset,invalid=invalid,evidence=evidence)


def export(estimator,threshold,metadata):
    trees=[]
    for item in estimator.estimators_:
        t=item.tree_;tree=[]
        for i in range(t.node_count):
            value=t.value[i][0];prob=float(value[1]/value.sum())
            tree.append([int(t.feature[i]) if t.children_left[i]>=0 else -1,float(t.threshold[i]),int(t.children_left[i]),int(t.children_right[i]),prob])
        trees.append(tree)
    feature_names=FEATURES if estimator.n_features_in_==len(FEATURES) else FEATURES_V1
    payload=dict(schema='windows-native-forest-v2' if feature_names==FEATURES else 'windows-native-forest-v1',event_schema='windows-event-v1',features=list(feature_names),horizon=HORIZON,threshold=threshold,trees=trees,**metadata)
    return dict(payload=payload,sha256=hashlib.sha256(canonical(payload)).hexdigest())


def evaluate(model,bags):
    totals=dict(tp=0,fn=0,fp=0,tn=0);variants={};sessions=[];start=time.process_time();num=0
    for bag in bags:
        row=bag['row'];scores=[model.score(x) for x in bag['vectors']];num+=len(scores)
        alert=next((i+1 for i,s in enumerate(scores) if s>=model.threshold),None)
        qualified=next((i+1 for i,s in enumerate(scores) if s>=model.threshold and bag['onset'] is not None and i+1>=bag['onset']),None)
        positive=row['kind']=='destructive';key=('tp' if qualified else 'fn') if positive else ('fp' if alert else 'tn')
        totals[key]+=1;v=variants.setdefault(row['campaign']['variant'],dict(tp=0,fn=0,fp=0,tn=0));v[key]+=1
        sessions.append(dict(id=row['id'],kind=row['kind'],variant=row['campaign']['variant'],profile=row['campaign'].get('profile','mixed'),onset_seq=bag['onset'],first_alert_seq=alert,qualified_alert_seq=qualified,events_after_onset=(qualified-bag['onset']) if qualified else None,invalid_files_at_alert=bag['invalid'].get(qualified) if qualified else None,invalid_files_before_alert=bag['invalid'].get(qualified-1,0) if qualified else None,peak_score=max(scores),pre_onset_alert=bool(positive and alert and alert<bag['onset']),events=len(scores)))
    cpu=time.process_time()-start
    return dict(**totals,per_variant=variants,sessions=sessions,cpu_seconds=cpu,events=num,events_per_cpu_second=num/max(cpu,1e-9))


def train(out,bundle_path):
    from sklearn.ensemble import RandomForestClassifier
    import numpy as np
    out=Path(out);spec=json.loads((out/'manifest.json').read_text());rows=spec['campaigns']
    if len({r['id'] for r in rows})!=len(rows) or len({r['campaign']['seed'] for r in rows})!=len(rows):raise AssertionError('campaign partition leakage')
    roles={role:[load(out,r) for r in rows if r['role']==role] for role in ('train','tune','calibrate')}
    identities=[(b['events'][0]['pid'],b['events'][0]['incarnation']) for bags in roles.values() for b in bags]
    if len(set(identities))!=len(identities):raise AssertionError('actor reuse across campaigns')
    X=[];y=[];weights=[]
    for bag in roles['train']:
        indices=list(range(0,len(bag['vectors']),4))
        for i in indices:
            X.append(bag['vectors'][i]);y.append(int(bag['row']['kind']=='destructive' and bag['onset'] is not None and i+1>=bag['onset']));weights.append(1/len(indices))
    fitting_start=time.perf_counter();candidates=[];best=None
    declarations=spec.get('model_candidates',[dict(depth=d,min_samples_leaf=l) for d,l in [(3,8),(5,8),(7,8),(5,20)]])
    for declaration in declarations:
        depth,leaf=declaration['depth'],declaration['min_samples_leaf']
        estimator=RandomForestClassifier(n_estimators=spec.get('trees_per_candidate',24),max_depth=depth,min_samples_leaf=leaf,random_state=spec['seed'],n_jobs=1,class_weight='balanced')
        estimator.fit(X,y,sample_weight=weights)
        benign=[max(estimator.predict_proba(b['vectors'])[:,1]) for b in roles['tune'] if b['row']['kind']=='benign']
        threshold=min(1.,float(np.nextafter(max(benign),np.inf)))
        model=Model(export(estimator,threshold,{}));ev=evaluate(model,roles['tune'])
        delays=[s['events_after_onset'] for s in ev['sessions'] if s['events_after_onset'] is not None]
        latency=sum(delays)/max(1,len(delays))
        rank=(ev['tp'],-ev['fp'],-latency,-sum(t.tree_.node_count for t in estimator.estimators_)) if spec['version']==2 else (ev['tp'],-ev['fp'],-sum(t.tree_.node_count for t in estimator.estimators_))
        candidates.append(dict(depth=depth,min_samples_leaf=leaf,threshold=threshold,tp=ev['tp'],fn=ev['fn'],fp=ev['fp'],tn=ev['tn'],mean_onset_event_delay=latency))
        if best is None or rank>best[0]:best=(rank,estimator)
    estimator=best[1]
    maxima=[float(max(estimator.predict_proba(b['vectors'])[:,1])) for b in roles['calibrate']]
    threshold=min(1.,float(np.nextafter(max(maxima),np.inf)))
    metadata=dict(name='Measured native campaign forest',cohort='Owned Windows native fixture campaigns',limitations='Harmless native fixture behavior only. Benign whole-file saves and destructive operations can be observationally indistinguishable. No real-world ransomware coverage claim.',training=dict(manifest_sha256=hashlib.sha256((out/'manifest.json').read_bytes()).hexdigest(),calibration_budget=0,calibration_session_maxima=maxima,candidates=candidates,selected_params=estimator.get_params(),holdout_variants=spec['holdout_variants'],holdout_profiles=spec.get('holdout_profiles',[]),selection_policy=spec.get('selection_policy','Maximize tuning recall then fewer false alerts then fewer tree nodes'),cutoff_policy=spec.get('cutoff_policy','Next float above largest benign calibration session maximum'),experiment=spec.get('experiment','v1')))
    # Freeze before opening test data. Never adapt this threshold after evaluation.
    bundle=export(estimator,threshold,metadata);write(bundle_path,bundle);model=Model(bundle_path)
    inference_fields=('schema','event_schema','features','horizon','threshold','trees')
    inference_sha=hashlib.sha256(canonical({k:bundle['payload'][k] for k in inference_fields})).hexdigest()
    freeze_sha=bundle['sha256'];write(out/'frozen-inference.json',bundle);write(out/'frozen-before-test.json',dict(sha256=freeze_sha,threshold=threshold,manifest_sha256=metadata['training']['manifest_sha256']))
    parity_max=0.
    for bags in roles.values():
        for bag in bags:
            reference=estimator.predict_proba(bag['vectors'])[:,1];actual=[model.score(x) for x in bag['vectors']]
            parity_max=max(parity_max,max(abs(float(a)-b) for a,b in zip(reference,actual)))
            if not np.allclose(reference,actual,atol=1e-14,rtol=0):raise AssertionError('training/runtime score parity failed')
            if list(reference>=threshold)!=[s>=threshold for s in actual]:raise AssertionError('decision parity failed')
    test=[load(out,r) for r in rows if r['role']=='test']
    test_ids=[(b['events'][0]['pid'],b['events'][0]['incarnation']) for b in test]
    if len(set(identities+test_ids))!=len(identities+test_ids):raise AssertionError('test actor leakage')
    # Test parity also checked without fitting or threshold modification.
    for bag in test:
        reference=estimator.predict_proba(bag['vectors'])[:,1];actual=[model.score(x) for x in bag['vectors']]
        parity_max=max(parity_max,max(abs(float(a)-b) for a,b in zip(reference,actual)))
        if not np.allclose(reference,actual,atol=1e-14,rtol=0) or list(reference>=threshold)!=[s>=threshold for s in actual]:raise AssertionError('test parity failed')
    evaluation=evaluate(model,test);calibration=evaluate(model,roles['calibrate'])
    # Isolated vs randomly interleaved actual held-out event streams.
    isolated={b['events'][0]['actor']:[model.score(x) for x in b['vectors']] for b in test}
    router=Router(model);positions=[0]*len(test);rng=random.Random(8871);remaining=list(range(len(test)))
    while remaining:
        i=rng.choice(remaining);bag=test[i];j=positions[i];e=bag['events'][j];got=router.add(e)
        if got['score']!=isolated[e['actor']][j]:raise AssertionError('interleaving changed score')
        positions[i]+=1
        if positions[i]==len(bag['events']):remaining.remove(i)
    # Evaluation metadata is excluded from inference and does not alter frozen trees/cutoff.
    bundle['payload']['evaluation']=dict(cohort=metadata['cohort'],**{k:evaluation[k] for k in ('tp','fn','fp','tn')},limitations=metadata['limitations'])
    if hashlib.sha256(canonical({k:bundle['payload'][k] for k in inference_fields})).hexdigest()!=inference_sha:raise AssertionError('frozen inference changed during test')
    bundle['sha256']=hashlib.sha256(canonical(bundle['payload'])).hexdigest();write(bundle_path,bundle)
    report=dict(test=evaluation,calibration=calibration,threshold=threshold,calibration_budget_met=calibration['fp']==0,calibration_budget_note='Zero observed calibration alerts' if calibration['fp']==0 else 'Zero-alert budget unattainable at score ceiling; threshold remains 1 and observed errors are reported.',inference_sha256=inference_sha,parity_max_abs_error=parity_max,parity_decisions_exact=True,interleaving_exact=True,bundle_bytes=Path(bundle_path).stat().st_size,fitting_seconds=time.perf_counter()-fitting_start,frozen_inference_sha256=freeze_sha,final_bundle_sha256=bundle['sha256'],manifest=spec,limitations=metadata['limitations'],heldout_variant_limit=spec['limitations'])
    write(out/'evaluation.json',report);print(json.dumps({k:v for k,v in report.items() if k not in ('test','calibration','manifest')},indent=2),flush=True);print('test', {k:evaluation[k] for k in ('tp','fn','fp','tn')},flush=True)



def replay_exported(out,bundle_path):
    """Replay frozen test streams without fitting or changing the exported model."""
    from raneval.windows_stream import History as LegacyHistory
    out=Path(out);spec=json.loads((out/'manifest.json').read_text())
    test=[load(out,r) for r in spec['campaigns'] if r['role']=='test']
    native=Model(bundle_path)
    for bag in test:
        history=native.history();bag['vectors']=[history.add(e) for e in bag['events']]
    native_result=evaluate(native,test)
    prior_path=out/'evaluation.json'
    if prior_path.exists():
        prior=json.loads(prior_path.read_text())
        for key in ('tp','fn','fp','tn','per_variant','sessions'):
            expected=prior['test'][key]
            actual=native_result[key]
            if key=='sessions':
                expected=[{k:v for k,v in item.items() if k!='profile'} for item in expected]
                actual=[{k:v for k,v in item.items() if k!='profile'} for item in actual]
            if actual!=expected:raise AssertionError('frozen test replay changed')
        if native.threshold!=prior['threshold']:raise AssertionError('frozen cutoff changed')
    legacy=Model(ROOT/'demo/windows_streaming/model.json')
    for bag in test:
        history=LegacyHistory();bag['vectors']=[history.add(e) for e in bag['events']]
    legacy_result=evaluate(legacy,test)
    result=dict(native=native_result,frozen_en2025_on_native=legacy_result,threshold=native.threshold,bundle_sha256=hashlib.sha256(Path(bundle_path).read_bytes()).hexdigest(),note='Read-only exported runtime replay, no fitting or cutoff changes; cohort is held-out owned native fixtures.')
    write(out/'evaluation-replay.json',result)
    print(json.dumps({name:{k:value[k] for k in ('tp','fn','fp','tn')} for name,value in [('native',native_result),('frozen_en2025_on_native',legacy_result)]}),flush=True)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['collect','train','evaluate','all']);p.add_argument('--experiment',choices=['v1','v2'],default='v1');p.add_argument('--out',type=Path);p.add_argument('--bundle',type=Path);a=p.parse_args()
    if a.out is None:a.out=ROOT/('runs/windows-native-campaigns-v2-20261118' if a.experiment=='v2' else 'runs/windows-native-campaigns-20261118')
    if a.bundle is None:a.bundle=a.out/'native-model.json' if a.experiment=='v2' else ROOT/'demo/windows_streaming/native-model.json'
    if a.action in ('collect','all'):collect(a.out,a.experiment)
    if a.action in ('train','all'):train(a.out,a.bundle)
    if a.action=='evaluate':replay_exported(a.out,a.bundle)
if __name__=='__main__':main()
