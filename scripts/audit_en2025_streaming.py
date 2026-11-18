"""Audit every extracted development report with streaming parsing; no call/report caps."""
import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import sys
import ijson
from raneval.windows_events import Projector

KEEP_ARGS = {'FileHandle','Handle','FileName','HandleName','Length','FileInformationClass','NumberOfBytesTransferred'}

def sha_file(path):
    with path.open('rb') as f: return hashlib.file_digest(f, 'sha256').hexdigest()

def project(path, capture, output):
    counts = Counter(); meta = {}; projector = None; call = None; arg = {}; index = 0
    sequence = hashlib.sha256(); pid_counts = Counter(); processes = 0; sample = None
    with path.open('rb') as f:
        for prefix, event, value in ijson.parse(f, use_float=True):
            if prefix == 'target.file.sha256' and event == 'string': sample = value
            if prefix == 'behavior.processes.item' and event == 'start_map':
                meta = {}; processes += 1; projector = None; index = 0
            if prefix.startswith('behavior.processes.item.'):
                leaf = prefix[len('behavior.processes.item.'):]
                if '.' not in leaf and event in ('string','number','null','boolean'):
                    meta[leaf] = value
            if prefix == 'behavior.processes.item.calls' and event == 'start_array':
                projector = Projector(capture, processes, meta, counts)
                pid_counts[str(meta.get('process_id'))] += 1
                for key in ('process_id','parent_id','first_seen'): counts['process_present_' + key] += meta.get(key) is not None
            if prefix == 'behavior.processes.item.calls.item' and event == 'start_map': call = {'arguments': {}}; index += 1
            if call is not None:
                base = 'behavior.processes.item.calls.item.'
                if prefix.startswith(base):
                    leaf = prefix[len(base):]
                    if '.' not in leaf and event in ('string','number','boolean','null') and leaf != 'arguments': call[leaf] = value
                    if leaf == 'arguments.item' and event == 'start_map': arg = {}
                    if leaf.startswith('arguments.item.') and event in ('string','number','boolean','null'):
                        arg[leaf.rsplit('.',1)[1]] = value
                    if leaf == 'arguments.item' and event == 'end_map' and arg.get('name') in KEEP_ARGS: call['arguments'][arg['name']] = arg.get('value')
                    if leaf.startswith('arguments.') and leaf.count('.') == 1 and event in ('string','number','boolean','null') and leaf.split('.')[1] in KEEP_ARGS: call['arguments'][leaf.split('.')[1]] = value
                if prefix == 'behavior.processes.item.calls.item' and event == 'end_map':
                    sequence.update((str(processes) + ':' + str(call.get('api')) + '\n').encode())
                    e = projector.call(call, index)
                    if e: output.write(json.dumps(e, separators=(',',':')) + '\n')
                    call = None
    counts['duplicate_pid_entries'] = sum(max(0,n-1) for n in pid_counts.values())
    return dict(counts=dict(counts), processes=processes, sample_sha256=sample or path.parent.name, sequence_sha256=sequence.hexdigest())

def summarize(audit):
    reports = audit['reports']
    audit['coverage_by_label'] = {}
    for label in ('benign', 'ransomware'):
        selected = [r for r in reports if r['label'] == label]
        counts = Counter()
        for r in selected: counts.update(r.get('counts', {}))
        audit['coverage_by_label'][label] = dict(selected_reports=len(selected),
            projected_reports=sum(r['status'] == 'projected' for r in selected), counts=dict(counts))
    audit['identity_duplicates'] = {}
    for field in ('raw_sha256', 'sample_sha256', 'sequence_sha256'):
        groups = {}
        for r in reports:
            if r.get(field): groups.setdefault(r[field], []).append(r['path'])
        audit['identity_duplicates'][field] = {k:v for k,v in groups.items() if len(v) > 1}
    audit['sample_member_identity_mismatches'] = [r['path'] for r in reports
        if r.get('sample_sha256') and r['sample_sha256'] != Path(r['path']).parent.name]
    return audit

def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('--root',type=Path,default=Path('data/pilot-reports')); p.add_argument('--output',type=Path,default=Path('data/processed/en2025-streaming')); a=p.parse_args(); a.output.mkdir(parents=True,exist_ok=True)
    records=[]; total=Counter()
    for label in ('benign','ransomware'):
        paths={x.resolve() for x in (a.root/label).glob('*/report.json')}
        manifest=a.root/(label+'-extraction.json')
        if manifest.exists():
            for entry in json.loads(manifest.read_text()).get('member_inventory',[]):
                if entry.get('status')=='extracted_report': paths.add((a.root/entry['member']).resolve())
        for path in sorted(paths):
            r=dict(path=str(path),label=label,status='error'); temp=None
            try:
                r['raw_sha256']=sha_file(path); r['raw_bytes']=path.stat().st_size
                dest=a.output/(r['raw_sha256']+'.jsonl.gz'); temp=dest.with_suffix('.tmp')
                with gzip.open(temp,'wt',encoding='utf8') as out: r.update(project(path,r['raw_sha256'],out))
                temp.replace(dest); r.update(status='projected',events=dest.name); total.update(r['counts'])
                if not r['counts'].get('calls'): r['status']='excluded_no_calls'
            except Exception as exc:
                r['error']=f'{type(exc).__name__}: {exc}'
                if temp: temp.unlink(missing_ok=True)
            records.append(r)
            print(f'{len(records)} {label} {r["status"]}',flush=True)
    audit=dict(schema='en2025-streaming-audit-v1',scope='All locally extracted development reports; publisher benign/ransomware total 1,652, not this subset',selected=len(records),publisher_reports=1652,dispositions=dict(Counter(r['status'] for r in records)),totals=dict(total),reports=records,limits=['Capture labels are weak session labels, not per-call or child-process truth.','Observed process-local order retained; interprocess chronology is not asserted. Repeated calls are not expanded.','File paths are hashed evidence; regular-file status is only a candidate. No completed byte count is inferred from requested Length.','4,096 live handles per actor; eviction explicitly counted. Unknown duplicate handles and binary setter destinations remain unknown.'])
    summarize(audit)
    (a.output/'audit.json').write_text(json.dumps(audit,indent=2),encoding='utf8')
    report=Path('output/research/en2025-streaming-audit.md'); report.parent.mkdir(parents=True,exist_ok=True)
    report.write_text('# EN2025 streaming audit\n\n'+audit['scope']+'\n\nSelected: '+str(len(records))+'; dispositions: '+json.dumps(audit['dispositions'])+'\n\nDenominators and counters:\n\n```json\n'+json.dumps(dict(total),indent=2)+'\n```\n\n'+'\n'.join('- '+s for s in audit['limits'])+'\n\nEvery report disposition, raw hash, exact full API sequence hash and sample identity is in `data/processed/en2025-streaming/audit.json`. Errors are never silently dropped.\n',encoding='utf8')
    with report.open('a',encoding='utf8') as out:
        out.write('\nExact identity duplicate groups: '+json.dumps({k:len(v) for k,v in audit['identity_duplicates'].items()})+'\n\nPer-class denominators:\n\n```json\n'+json.dumps(audit['coverage_by_label'],indent=2)+'\n```\n')

if __name__=='__main__': main()
