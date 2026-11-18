"""Read-only miss analysis for the frozen Windows baseline; never deploys or refits."""
import argparse
from collections import Counter, defaultdict
import gzip
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import queue
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from raneval.windows_stream import Model, History, FEATURES, OPS, Router


def describe(model, history, event):
    x = history.vector()
    contributions = dict(zip(FEATURES, (w * value for w, value in zip(model.weights, x))))
    return {'score': model.score(x), 'actor': event['actor'], 'pid': event['pid'],
            'seq': event['seq'], 'event_op': event['op'], 'event_outcome': event['outcome'],
            'event_target_kind': event['target_kind'], 'window_size': len(history.events),
            'operations': {k:v for k,v in history.ops.items() if v}, 'outcomes': {k:v for k,v in history.outcomes.items() if v},
            'target_kinds': dict(history.kinds), 'features': dict(zip(FEATURES, x)),
            'logit_bias': model.bias, 'logit_contributions': contributions,
            'successful_candidate_mutations_in_window': sum(e['outcome'] == 'success' and e['target_kind'] == 'file_candidate' and e['op'] in ('write','resize','delete','rename') for e in history.events)}


def analyze_capture(model, path, record):
    actor = None
    history = None
    best = None
    sampled = None
    events = 0
    actors = 0
    operations = Counter()
    for_line = gzip.open(path, 'rt', encoding='utf8')
    with for_line:
        for line in for_line:
            event = json.loads(line)
            if actor != event['actor']:
                if history is not None:
                    score = model.score(history.vector())
                    sampled = score if sampled is None else max(sampled, score)
                history = History()
                actor = event['actor']
                actors += 1
            x = history.add(event)
            score = model.score(x)
            if best is None or score > best['score']:
                best = describe(model, history, event)
            if history.seq == 1 or history.seq % 16 == 0:
                sampled = score if sampled is None else max(sampled, score)
            events += 1
            operations[event['op']] += 1
    if history is not None:
        sampled = max(sampled, model.score(history.vector()))
    if best is None:
        raise ValueError('Empty capture cannot silently receive a benign score')
    return {**record, 'events': events, 'actors': actors, 'operations': dict(operations),
            'maximum': best['score'], 'sampled_maximum': sampled, 'peak': best,
            'alert': best['score'] >= model.threshold}


def confusion(rows, threshold):
    counts = Counter()
    for row in rows:
        positive = row['label'] == 'ransomware'
        alert = threshold is not None and row['maximum'] >= threshold
        counts['tp' if positive and alert else 'fn' if positive else 'fp' if alert else 'tn'] += 1
    return {key: counts[key] for key in ('tp', 'fn', 'fp', 'tn')}


def quantiles(values):
    ordered = sorted(values)
    def at(fraction):
        position = (len(ordered) - 1) * fraction
        left = int(position)
        right = min(left + 1, len(ordered) - 1)
        return ordered[left] + (ordered[right] - ordered[left]) * (position - left)
    return dict(zip(('min', 'q25', 'median', 'q75', 'max'), (at(f) for f in (0, .25, .5, .75, 1))))


def native_diagnostic(model):
    if os.name != 'nt':
        return {'available': False, 'reason': 'Actual Windows workers required'}
    spec = importlib.util.spec_from_file_location('diagnostic_native_agent', ROOT / 'demo/windows_streaming/agent.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    agent = module.Agent('http://127.0.0.1:8767', 'diagnostic-local-only-not-sent-000000000000')
    router = Router(model)
    jobs = {kind: uuid.uuid4().hex for kind in ('benign', 'destructive')}
    profiles = {}
    final_evidence = {}
    def record(**payload):
        event = payload.get('event')
        if event is not None:
            result = router.add(event)
            profile = profiles.setdefault(event['job'], {'kind': next(k for k, v in jobs.items() if v == event['job']),
                'events': 0, 'operations': Counter(), 'peak': None, 'last': None,
                'all_successful_known_file_events': True})
            profile['events'] += 1
            profile['operations'][event['op']] += 1
            profile['all_successful_known_file_events'] &= event['outcome'] == 'success' and event['target_kind'] == 'file_candidate'
            history = router.actors[event['actor']]
            if profile['peak'] is None or result['score'] > profile['peak']['score']:
                profile['peak'] = describe(model, history, event)
            profile['last'] = describe(model, history, event)
        for item in payload.get('evidence', []):
            final_evidence[(item['job'], item['file'])] = item
    agent.update = record
    roots = []
    try:
        for kind, job in jobs.items():
            agent.start({'job': job, 'kind': kind})
            roots.append(agent.jobs[job]['root'])
        deadline = time.monotonic() + 25
        while agent.jobs and time.monotonic() < deadline:
            try:
                job, payload = agent.events.get(timeout=1)
            except queue.Empty:
                continue
            agent.consume(job, payload)
        if agent.jobs:
            raise RuntimeError('Diagnostic workers did not finish within their bound')
        for job, profile in profiles.items():
            items = [value for (owner, _), value in final_evidence.items() if owner == job]
            profile['files'] = len(items)
            profile['invalid_files'] = sum(not item['valid'] for item in items)
            profile['operations'] = dict(profile['operations'])
            profile['alert'] = profile['peak']['score'] >= model.threshold
        return {'available': True, 'mode': 'Concurrent real native workers, no HTTP/service mutation',
                'profiles': list(profiles.values()), 'owned_roots_removed': all(not p.exists() for p in roots)}
    finally:
        agent.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=ROOT / 'runs/windows-streaming-diagnostics-20261118')
    parser.add_argument('--native', action='store_true')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    model_path = ROOT / 'demo/windows_streaming/model.json'
    original_bytes = model_path.read_bytes()
    model = Model(model_path)
    split = json.loads((ROOT / 'demo/windows_streaming/split.json').read_text())
    rows = []
    for index, record in enumerate(split['reports'], 1):
        path = ROOT / 'data/processed/en2025-streaming' / (record['raw_sha256'] + '.jsonl.gz')
        rows.append(analyze_capture(model, path, record))
        if index % 60 == 0:
            print('analyzed', index, flush=True)
    (args.out / 'capture-peaks.json').write_text(json.dumps(rows, indent=2), encoding='utf8')
    evaluation = json.loads((ROOT / 'demo/windows_streaming/evaluation.json').read_text())
    test = [r for r in rows if r['role'] == 'test']
    measured = confusion(test, model.threshold)
    assert measured == {key: evaluation['metrics']['test'][key] for key in measured}
    benign_calibration = [r['maximum'] for r in rows if r['role'] == 'calibrate' and r['label'] == 'benign']
    allowed = math.floor(.05 * len(benign_calibration))
    boundary = sorted(benign_calibration, reverse=True)[allowed]
    five_percent = math.nextafter(boundary, math.inf)
    policies = []
    for name, threshold in (('frozen_deployed', model.threshold), ('diagnostic_5pct_calibration_budget', five_percent), ('diagnostic_fixed_0.5', .5)):
        policies.append({'name': name, 'threshold': threshold,
            'benign_calibration_alerts': sum(score >= threshold for score in benign_calibration),
            'test_confusion': confusion(test, threshold), 'deployed': name == 'frozen_deployed'})
    weights = dict(zip(FEATURES, model.weights))
    # Relax joint feature constraints: each equality/occupancy fraction <=1;
    # op fractions sum to1. Thus this is an optimistic upper bound, not a fit.
    bound_logit = model.bias + weights['file_candidate'] + max(weights['op_' + op] for op in OPS)
    bound_logit += sum(max(0, weights[name]) for name in ('unique_targets', 'unique_write_targets', 'read_write_overlap', 'occupancy'))
    upper_bound = 1 / (1 + math.exp(-bound_logit))
    duplicate = {'schema': 'windows-event-v1', 'actor': 'diagnostic', 'pid': 1, 'incarnation': 'diagnostic',
        'seq': 1, 'op': 'duplicate', 'outcome': 'success', 'target': None, 'target_kind': 'unknown'}
    duplicate_score = model.score(History().add(duplicate))
    summaries = {}
    for role in ('train', 'tune', 'calibrate', 'test'):
        for label in ('benign', 'ransomware'):
            selected = [r for r in rows if r['role'] == role and r['label'] == label]
            summaries[role + '/' + label] = {'captures': len(selected), 'maxima': quantiles([r['maximum'] for r in selected]),
                'alerts': sum(r['alert'] for r in selected),
                'peaks_at_first_actor_event': sum(r['peak']['seq'] == 1 for r in selected),
                'peaks_equal_calibration_boundary': sum(r['maximum'] == model.payload['calibration']['maximum'] for r in selected),
                'peak_operations': dict(Counter(r['peak']['event_op'] for r in selected)),
                'peaks_without_successful_file_mutation': sum(r['peak']['successful_candidate_mutations_in_window'] == 0 for r in selected)}
    native = native_diagnostic(model) if args.native else {'available': False, 'reason': '--native not supplied'}
    assert model_path.read_bytes() == original_bytes, 'Frozen model was modified during analysis'
    result = {'frozen_model_sha256': json.loads(original_bytes)['sha256'],
        'frozen_file_sha256': hashlib.sha256(original_bytes).hexdigest(),
        'test_confusion_reproduced': measured, 'summaries': summaries,
        'top_benign_calibration': sorted([r for r in rows if r['role'] == 'calibrate' and r['label'] == 'benign'], key=lambda r: -r['maximum'])[:5],
        'threshold_diagnostics_only': policies,
        'first_success_unknown_duplicate_score': duplicate_score,
        'known_successful_file_stream_upper_bound': {'score': upper_bound, 'logit': bound_logit,
            'assumptions': 'All event outcomes success, all target_kind file_candidate, fractions in[0,1], op fractions sum to1; joint constraints relaxed.'},
        'native': native, 'model_unchanged': True}
    (args.out / 'diagnostics.json').write_text(json.dumps(result, indent=2), encoding='utf8')
    print(json.dumps({'test': measured, 'policies': policies, 'known_file_upper_bound': upper_bound,
                      'native_profiles': [{k: p[k] for k in ('kind', 'events', 'invalid_files', 'alert')} for p in native.get('profiles', [])]}, indent=2))


if __name__ == '__main__':
    main()
