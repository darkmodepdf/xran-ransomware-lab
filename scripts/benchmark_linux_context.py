"""Compare a frozen contextual GRU on independent benign Linux captures."""

import argparse
from collections import Counter, defaultdict
from itertools import product
import json
import math
from pathlib import Path

import torch
import torch.nn.functional as F

from benchmark_linux import BENIGN, RANSOMWARE, validate_cohort
from refit_linux_gru import (
    ALPHA, DEVICE, HARD_ENDPOINTS, NAMED_FAMILIES, ROTATION, calibrate,
    encode_traces, keyed_tables, outcome, score, selection_rank,
)
from raneval import context, context_score
from raneval.context_score import ContextGRU, load_context_bundle, score_context_blocks
from raneval.core import EARLY_OBSERVATIONS, load_traces
from raneval.score import load_bundle
from raneval.train import atomic_json, atomic_torch, digest, make_endpoints


BASELINES = ('counts', 'cnn', 'gru', 'gru_refit')
CONTEXT_ID = 'gru_context'
PENALTIES = (0.25, 0.1, 0.04, 0.015, 0.005, 0.002)
SUPPRESSION_CAPS = (0.10, 0.25, 0.5, 1.0)
CONTEXT_GATES = ('concentrated', 'repeat', 'all')


def read_contextual(path, label, horizon):
    traces, sha256 = load_traces(path)
    provenance = {}
    events = {}
    detail = 'workload' if label == BENIGN else 'family'
    with path.open(encoding='utf-8') as stream:
        for line in stream:
            if not line.strip():
                continue
            row = json.loads(line)
            trace_id = row['trace_id']
            if row['label'] != label or not row['apis']:
                raise ValueError(f'Invalid label or empty context capture: {trace_id}')
            for field in ('capture', detail, 'source'):
                if not isinstance(row[field], str) or not row[field].strip():
                    raise ValueError(f'Invalid {field} for {trace_id}')
            observations = row['events']
            if (not isinstance(observations, list) or len(observations) != len(row['apis'])
                    or any(not isinstance(event, dict) or event.get('op') != op
                           for op, event in zip(row['apis'], observations))):
                raise ValueError(f'Operation and context streams differ for {trace_id}')
            timings = row.get('elapsed_ms', row.get('times_ms'))
            if timings is not None and (
                not isinstance(timings, list) or len(timings) != len(observations)
                or any(type(t) not in (int, float) or not math.isfinite(t) or t < 0 for t in timings)
                or timings[0] != 0 or any(a > b for a, b in zip(timings, timings[1:]))
            ):
                raise ValueError(f'Invalid timing for {trace_id}')
            provenance[trace_id] = {field: row[field] for field in ('capture', detail, 'source')}
            provenance[trace_id]['elapsed_ms'] = timings
            events[trace_id] = observations[:horizon]
    return traces, provenance, events, sha256


def validate_holdout(benign, positive, provenance, historical, historical_provenance, earlier_benign, horizon):
    historical_positives = {trace.trace_id: trace for trace in historical if trace.label == RANSOMWARE}
    if {trace.trace_id for trace in positive} != historical_positives.keys():
        raise ValueError('Contextual CRIBA rows must match the original positive train and test cohorts')
    for trace in positive:
        prior = historical_provenance[trace.trace_id]
        current = provenance[trace.trace_id]
        if trace != historical_positives[trace.trace_id] or any(prior[key] != current[key] for key in ('family', 'capture')):
            raise ValueError(f'Contextual CRIBA projection differs from the original cohort: {trace.trace_id}')

    prior_ids = {trace.trace_id for trace in historical}
    prior_groups = {trace.group_id for trace in historical}
    prior_captures = {item['capture'] for item in historical_provenance.values()}
    prior_operations = {trace.apis[:horizon] for trace in historical}
    for prior_path in earlier_benign:
        with prior_path.open(encoding='utf-8') as stream:
            for line in stream:
                if not line.strip():
                    continue
                row = json.loads(line)
                prior_ids.add(row['trace_id'])
                prior_groups.add(row['group_id'])
                prior_captures.add(row['capture'])
                prior_operations.add(tuple(row['apis'][:horizon]))
    for trace in benign:
        capture = provenance[trace.trace_id]['capture']
        operations = trace.apis[:horizon]
        if (trace.trace_id in prior_ids or trace.group_id in prior_groups or capture in prior_captures
                or operations in prior_operations):
            raise ValueError(f'Capture, group or exact operation stream reused: {trace.trace_id}')
        prior_ids.add(trace.trace_id)
        prior_groups.add(trace.group_id)
        prior_captures.add(capture)
        prior_operations.add(operations)


def rows_for(traces, events, block_size):
    return {trace.trace_id: torch.tensor(context.context_rows(events[trace.trace_id], block_size), dtype=torch.float32)
            for trace in traces}


@torch.no_grad()
def base_logits(model, tokens, block_size):
    return torch.cat([model(torch.tensor([tokens[start:start + block_size]], dtype=torch.int64))[0]
                      for start in range(0, len(tokens), block_size)])


def training_examples(base, traces, encoded, contextual, provenance, block_size):
    _, sampled = make_endpoints(traces, encoded, 24, 2769, 'early', 2.0)
    endpoints = defaultdict(dict)
    for trace_id, position, _, weight in sampled:
        endpoints[trace_id][position - 1] = weight

    vectors, offsets, labels, weights, receipt = [], [], [], [], {}
    for trace in traces:
        trace_id = trace.trace_id
        logits = base_logits(base, encoded[trace_id], block_size)
        positive = trace.label == RANSOMWARE
        rotation = provenance[trace_id].get('workload') == ROTATION
        search = logits[:EARLY_OBSERVATIONS] if positive else logits
        hard = torch.argsort(search, descending=True, stable=True)[:HARD_ENDPOINTS].tolist()
        share = 0.7 if rotation else 0.5
        selected = {position: weight * (1 - share) for position, weight in endpoints[trace_id].items()}
        for position in hard:
            selected[position] = selected.get(position, 0.0) + share / len(hard)
        indices = sorted(selected)
        vectors.append(contextual[trace_id][indices])
        offsets.append(logits[indices])
        labels.extend([float(positive)] * len(indices))
        influence = 2.0 if rotation else 1.0
        weights.extend(influence * selected[position] for position in indices)
        receipt[trace_id] = {'sampled_endpoints': sorted(pos + 1 for pos in endpoints[trace_id]),
                             'hard_endpoints': [pos + 1 for pos in hard]}
    y = torch.tensor(labels, dtype=torch.float64)
    w = torch.tensor(weights, dtype=torch.float64)
    for value in (0, 1):
        mask = y == value
        w[mask] *= 0.5 / w[mask].sum()
    return torch.cat(vectors).double(), torch.cat(offsets).double(), y, w, receipt


def fit_correction(x, offsets, y, example_weights, penalty):
    # Keep zero context neutral. Scaling from weighted training RMS regularizes
    # the correction in comparable units even for rare behavior.
    scale = (x.square().T @ example_weights).sqrt().clamp_min(0.1)
    normalized = x / scale
    weight = torch.zeros(x.shape[1], dtype=torch.float64, requires_grad=True)
    optimizer = torch.optim.LBFGS([weight], max_iter=120, line_search_fn='strong_wolfe')

    def objective():
        optimizer.zero_grad()
        logits = offsets + normalized @ weight
        loss = F.binary_cross_entropy_with_logits(logits, y, weight=example_weights, reduction='sum')
        loss = loss + penalty * weight.square().sum()
        if not loss.isfinite().item():
            raise ValueError('Nonfinite contextual readout objective')
        loss.backward()
        return loss

    optimizer.step(objective)
    return (weight.detach() / scale).float()


def score_context(model, traces, encoded, contextual, block_size):
    return {trace.trace_id: list(score_context_blocks(model, encoded[trace.trace_id], contextual[trace.trace_id],
                                                      block_size, DEVICE)) for trace in traces}


def paired_benign(refit, enriched, workload=None):
    def subset(captures):
        return {row['trace_id']: row['first_event'] is not None for row in captures
                if workload is None or row['workload'] == workload}

    old, new = subset(refit), subset(enriched)
    if old.keys() != new.keys():
        raise ValueError('Paired benign comparison needs identical captures')
    removed = sum(old[key] and not new[key] for key in old)
    added = sum(new[key] and not old[key] for key in old)
    discordant = removed + added
    p_value = (min(1.0, 2.0 * sum(math.comb(discordant, i) for i in range(min(removed, added) + 1)) / 2**discordant)
               if discordant else 1.0)
    return {'captures': len(old), 'removed_alerts': removed, 'added_alerts': added,
            'alert_delta': added - removed, 'paired_exact_p': p_value}


def coverage(traces, events):
    summary = defaultdict(Counter)
    for trace in traces:
        role = trace.role if trace.label == BENIGN else f'criba_{trace.role}'
        for event in events[trace.trace_id]:
            counts = summary[role]
            counts['events'] += 1
            counts['actor'] += event.get('actor') is not None
            counts['file'] += event.get('file') is not None
            counts['directory'] += event.get('directory') is not None
            counts['writes'] += event['op'] == 'write'
            counts['write_size'] += event.get('bytes_changed') is not None
    return dict(summary)


def select_context(base, train, tune, regression, encoded, contextual, provenance, block_size, out, bounded):
    x, offsets, y, weights, endpoints = training_examples(base, train, encoded, contextual, provenance, block_size)
    atomic_json(out / 'readout-endpoints.json', endpoints)
    candidates = []
    best = None
    selectable = tune + regression
    frozen_logits = {trace.trace_id: base_logits(base, encoded[trace.trace_id], block_size) for trace in selectable}
    rotation_ids = [trace.trace_id for trace in tune if provenance[trace.trace_id]['workload'] == ROTATION]
    gates = CONTEXT_GATES if bounded else ('all',)
    caps = SUPPRESSION_CAPS if bounded else (None,)
    fitted = {penalty: fit_correction(x, offsets, y, weights, penalty) for penalty in PENALTIES}
    for penalty, gate, cap in product(PENALTIES, gates, caps):
        model = ContextGRU(base, fitted[penalty], cap, gate).eval()
        scores = {key: (logits + model.correction(contextual[key])).double().sigmoid().tolist()
                  for key, logits in frozen_logits.items()}
        threshold = calibrate(scores, tune)
        diagnostics = outcome(scores, tune + regression, provenance, threshold)
        rank = selection_rank(diagnostics)
        if bounded:
            hardest_rotation = sorted((max(scores[key]) for key in rotation_ids), reverse=True)[:3]
            rank += (math.fsum(hardest_rotation) / len(hardest_rotation),)
        candidates.append({'penalty': penalty, 'gate': gate, 'max_suppression': cap,
                           'rank': rank, 'tuning_threshold': threshold,
                           'tuning_rotation': diagnostics['workloads'][ROTATION],
                           'regression_families': diagnostics['families']})
        if best is None or rank < best[0]:
            best = (rank, penalty, model)
    _, penalty, model = best
    atomic_json(out / 'selection.json', {
        'penalty': penalty, 'gate': model.gate, 'max_suppression': model.max_suppression,
        'candidates': candidates, 'context_weight': model.context_weight.tolist(),
        'passed_known_early_gate': -best[0][0] == len(regression),
        'rule': ('Maximize known-family alerts by event 120, then minimize tuning log-rotation alerts, '
                 'tuning benign alerts and capped known-family delay. The bounded version also prefers lower '
                 'maxima among the three hardest tuning rotations as a tiebreaker. Use preset candidate order for ties.'),
        'selection_captures': {'train': [trace.trace_id for trace in train],
                               'tune': [trace.trace_id for trace in tune],
                               'known_regression': [trace.trace_id for trace in regression]},
    })
    print(f'Selected context penalty {penalty}, gate {model.gate}, cap {model.max_suppression}. '
          f'Known early gate {-best[0][0]}/{len(regression)} before fresh calibration and test scoring.', flush=True)
    return penalty, model


def run(args):
    torch.manual_seed(123)
    torch.use_deterministic_algorithms(True)
    torch.set_num_threads(args.cpu_threads)
    prior = json.loads((args.prior_refit / 'benchmark.json').read_bytes())
    prior_hashes = {item['id']: item['bundle_sha256'] for item in prior['models']}
    loaded = {name: load_bundle(args.prior_refit / f'{name}.pt', DEVICE, prior_hashes[name]) for name in BASELINES}
    base, anchored_gru, _ = loaded['gru_refit']
    horizon, block_size = base['horizon'], base['block_size']
    if not horizon or not block_size or any(bundle['horizon'] != horizon or bundle['block_size'] != block_size
                                           or bundle['vocabulary'] != base['vocabulary']
                                           for bundle, _, _ in loaded.values()):
        raise ValueError('The frozen models need the same positive horizon, block size and vocabulary')
    historical, historical_hash = load_traces(args.benchmark_data)
    audit = json.loads(args.benchmark_audit.read_bytes())
    historical_provenance, _, _, _ = validate_cohort(historical, audit, historical_hash, horizon)
    prior_identity = prior['evaluation']
    audit_hash = digest(args.benchmark_audit)
    if (historical_hash != prior_identity['benchmark_data_sha256']
            or audit_hash != prior_identity['benchmark_audit_sha256']
            or digest(args.earlier_benign) != prior_identity['benign_sha256']):
        raise ValueError('Historical data do not match the frozen token-only comparison')

    benign, benign_provenance, benign_events, benign_hash = read_contextual(args.benign, BENIGN, horizon)
    positive, positive_provenance, positive_events, positive_hash = read_contextual(args.positive, RANSOMWARE, horizon)
    provenance = {**benign_provenance, **positive_provenance}
    events = {**benign_events, **positive_events}
    validate_holdout(benign, positive, provenance, historical, historical_provenance,
                     [args.earlier_benign, *args.additional_prior_benign], horizon)
    train = sorted((trace for trace in benign + positive if trace.role == 'train'), key=lambda trace: trace.trace_id)
    tune = [trace for trace in benign if trace.role == 'tune']
    calibration = [trace for trace in benign if trace.role == 'calibrate']
    test = [trace for trace in benign if trace.role == 'test']
    regression = [trace for trace in positive if trace.role == 'test']
    if {positive_provenance[t.trace_id]['family'] for t in regression} != NAMED_FAMILIES:
        raise ValueError('The known positive regression requires DarkSide and Erebus')
    if min(len(calibration), len(test)) < 40 or len(tune) < 20:
        raise ValueError('Need at least 40 fresh calibration, 40 fresh test and 20 tuning benign captures')
    for subset in (train, tune, calibration, test):
        if not any(provenance[row.trace_id].get('workload') == ROTATION for row in subset):
            raise ValueError('Every benign role needs independently captured log rotation runs')

    args.out.mkdir(parents=True, exist_ok=False)
    identity = {
        'benchmark_data_sha256': historical_hash, 'benchmark_audit_sha256': audit_hash,
        'benign_sha256': benign_hash, 'positive_sha256': positive_hash,
        'source_bundles_sha256': {name: loaded[name][2] for name in BASELINES},
        'code_sha256': {Path(path).name: digest(Path(path)) for path in (__file__, context.__file__, context_score.__file__)},
        'pytorch': str(torch.__version__), 'cpu_threads': args.cpu_threads,
        'block_size': block_size, 'horizon': horizon, 'penalties': PENALTIES,
        'additional_prior_benign_sha256': [digest(path) for path in args.additional_prior_benign],
        'context_gates': CONTEXT_GATES if args.bounded else ('all',),
        'suppression_caps': SUPPRESSION_CAPS if args.bounded else (),
    }
    atomic_json(args.out / 'manifest.json', identity)
    development = train + tune + regression
    development_rows = rows_for(development, events, block_size)
    penalty, model = select_context(anchored_gru, train, tune, regression, encode_traces(development, base),
                                    development_rows, provenance, block_size, args.out, args.bounded)
    features = {'version': 1, 'feature_names': list(context.CONTEXT_FEATURE_NAMES),
                'weight': model.context_weight, 'gate': model.gate, 'max_suppression': model.max_suppression}
    context_path = args.out / f'{CONTEXT_ID}.pt'
    # Lock weights on disk before computing any fresh calibration or test scores.
    atomic_torch(context_path, {**base, 'version': 2, 'identity': {**identity, 'variant': CONTEXT_ID},
                                'context': features, 'thresholds': []})
    context_bundle, model, _ = load_context_bundle(context_path, DEVICE)
    judged = calibration + test + regression
    encoded = encode_traces(judged, base)
    contextual = {**rows_for(calibration + test, events, block_size),
                  **{trace.trace_id: development_rows[trace.trace_id] for trace in regression}}

    results = []
    fresh_alerts = {}
    for name in (*BASELINES, CONTEXT_ID):
        if name == CONTEXT_ID:
            calibration_scores = score_context(model, calibration, encoded, contextual, block_size)
            threshold = calibrate(calibration_scores, calibration)
            test_scores = score_context(model, test + regression, encoded, contextual, block_size)
            exported = context_bundle
        else:
            exported, baseline, _ = loaded[name]
            calibration_scores = score(baseline, calibration, encoded, block_size)
            threshold = calibrate(calibration_scores, calibration)
            test_scores = score(baseline, test + regression, encoded, block_size)
        fresh = outcome(test_scores, test, provenance, threshold)
        named = outcome(test_scores, regression, provenance, threshold)
        path = args.out / f'{name}.pt'
        atomic_torch(path, {**exported, 'thresholds': [threshold]})
        atomic_json(args.out / f'{name}-calibration.json', threshold)
        atomic_json(args.out / f'{name}-alerts.json', {'fresh_test': fresh['rows'], 'regression': named['rows']})
        fresh_alerts[name] = fresh['rows']
        results.append({
            'id': name,
            'calibration': {'alerts': threshold['alerts'], 'total': threshold['n'],
                            'allowed': math.floor(ALPHA * threshold['n']),
                            'threshold': threshold['tau'], 'mode': threshold['mode']},
            'benign_test': fresh['benign'], 'ransomware_test': fresh['ransomware'],
            'benign_workloads': fresh['workloads'], 'regression_families': named['families'],
            'bundle_sha256': digest(path),
        })
        print(f'{name}: {fresh["workloads"][ROTATION]} rotation alerts, {named["ransomware"]["early_alerts"]} known early alerts.',
              flush=True)

    old, new = fresh_alerts['gru_refit'], fresh_alerts[CONTEXT_ID]
    capture_counts = dict(Counter(trace.role for trace in benign))
    report = {
        'schema': 'raneval-linux-benchmark-v1', 'title': 'Linux GRU with file and process context',
        'method': ('A learned context correction extends the frozen token-only GRU refit. '
                   + ('It can only lower the original score, with the reduction capped. ' if args.bounded else '')
                   + 'It uses past and current '
                   'system-call behavior within each reset block. Model selection preceded fresh scoring. Each model '
                   'received its own threshold from the same fresh benign calibration captures.'),
        'provenance': [
            {'name': 'CRIBA', 'url': 'https://github.com/dsrhaslab/criba',
             'detail': 'Previously recorded Linux ransomware training captures and known-family regression.'},
            {'name': 'Fresh benign Linux recordings',
             'detail': 'Genuine successful operations from independently recorded runs of local container workloads.'},
        ],
        'limitations': [
            'Fresh held-out captures are benign. The five DarkSide and Erebus captures were previously evaluated '
            'and influenced model selection.',
            'Benign and positive captures use different collectors. Collector and host effects can contribute to the '
            'measured behavior. Benign captures repeat workloads on one Linux environment.',
            'Alerts are per capture. Alert positions count retained successful operations and do not measure file damage.',
        ],
        'budget': {'target_rate': ALPHA, 'unit': 'benign capture'}, 'early_event_horizon': EARLY_OBSERVATIONS,
        'models': [{k: v for k, v in result.items() if k not in ('regression_families', 'benign_workloads')}
                   for result in results],
        'families': [], 'regression_families': keyed_tables(results, 'regression_families'),
        'benign_workloads': keyed_tables(results, 'benign_workloads'),
        'evaluation': {**identity, 'capture_counts': capture_counts, 'fresh_positive_captures': 0,
                       'regression_captures': len(regression), 'training_positive_captures': len(train) - capture_counts['train'],
                       'context': {'feature_names': list(context.CONTEXT_FEATURE_NAMES), 'penalty': penalty,
                                   'gate': model.gate, 'max_suppression': model.max_suppression,
                                   'coverage': coverage(benign + positive, events),
                                   'paired_against_gru_refit': {'all': paired_benign(old, new),
                                                               'log_rotation': paired_benign(old, new, ROTATION)}}},
    }
    atomic_json(args.out / 'benchmark.json', report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prior-refit', type=Path, default=Path('runs/linux-gru-refit'))
    parser.add_argument('--benchmark-data', type=Path, default=Path('data/processed/linux-benchmark.jsonl'))
    parser.add_argument('--benchmark-audit', type=Path, default=Path('data/processed/linux-benchmark-audit.json'))
    parser.add_argument('--earlier-benign', type=Path, default=Path('data/processed/linux-gru-rotation-benign.jsonl'))
    parser.add_argument('--additional-prior-benign', type=Path, action='append', default=[])
    parser.add_argument('--benign', type=Path, default=Path('data/processed/linux-context-benign.jsonl'))
    parser.add_argument('--positive', type=Path, default=Path('data/processed/linux-gru-context-criba.jsonl'))
    parser.add_argument('--out', type=Path, default=Path('runs/linux-gru-context'))
    parser.add_argument('--cpu-threads', type=int, default=1)
    parser.add_argument('--bounded', action='store_true', help='Compare suppressive context corrections with preset caps and gates')
    args = parser.parse_args()
    if args.cpu_threads <= 0:
        parser.error('--cpu-threads must be positive')
    run(args)


if __name__ == '__main__':
    main()
