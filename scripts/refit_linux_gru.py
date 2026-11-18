"""Select a causal GRU readout on development data and compare on fresh captures."""

import argparse
from collections import Counter, defaultdict
import copy
import hashlib
import json
import math
from pathlib import Path
import random

import torch
import torch.nn.functional as F

from benchmark_linux import BENIGN, RANSOMWARE, summarize_positives, validate_cohort
from raneval.core import EARLY_OBSERVATIONS, Trace, choose_threshold, encode, first_alert, load_traces, score_blocks
from raneval.score import load_bundle
from raneval.train import atomic_json, atomic_torch, digest, make_endpoints


ALPHA = 0.05
ROTATION = 'Log rotation'
NAMED_FAMILIES = frozenset({'DarkSide', 'Erebus'})
READOUT_PENALTIES = (0.01, 0.05, 0.2, 1.0)
HARD_ENDPOINTS = 16
DEVICE = torch.device('cpu')


def read_fresh(path, label, horizon, old, old_provenance):
    if path is None:
        return [], {}
    ids = {trace.trace_id for trace in old}
    groups = {trace.group_id for trace in old}
    captures = {row['capture'] for row in old_provenance.values()}
    processed_old = {trace.apis[:horizon] for trace in old}
    seen_groups = set()
    seen_events = set()
    traces = []
    provenance = {}
    allowed_roles = {'test'} if label == RANSOMWARE else {'train', 'tune', 'calibrate', 'test'}
    with path.open(encoding='utf-8') as stream:
        for line in stream:
            row = json.loads(line)
            trace_id, group, capture = (row[k] for k in ('trace_id', 'group_id', 'capture'))
            if (row['label'] != label or row['role'] not in allowed_roles
                    or any(not isinstance(x, str) or not x for x in (trace_id, group, capture, row['source']))):
                raise ValueError(f'Invalid fresh capture metadata for {trace_id}')
            if trace_id in ids or capture in captures or group in groups:
                raise ValueError(f'Fresh capture overlaps an earlier capture or group: {trace_id}')
            if label == BENIGN and group in seen_groups:
                raise ValueError(f'Expected one fresh benign trace per capture: {trace_id}')
            seen_groups.add(group)
            ids.add(trace_id)
            captures.add(capture)

            operations = row['apis']
            if not isinstance(operations, list) or not operations or any(type(token) is not str for token in operations):
                raise ValueError(f'Invalid scored event sequence for {trace_id}')
            operations = tuple(operations[:horizon])
            if operations in processed_old or operations in seen_events:
                raise ValueError(f'Fresh input has an exact capped sequence overlap: {trace_id}')
            seen_events.add(operations)

            field = 'family' if label == RANSOMWARE else 'workload'
            detail = row[field]
            if not isinstance(detail, str) or not detail.strip():
                raise ValueError(f'Invalid {field} for {trace_id}')
            elapsed = row.get('elapsed_ms', row.get('times_ms'))
            if elapsed is not None:
                if (not isinstance(elapsed, list) or len(elapsed) < len(operations)
                        or any(type(x) not in (int, float) or not math.isfinite(x) or x < 0 for x in elapsed)
                        or elapsed[0] != 0 or any(left > right for left, right in zip(elapsed, elapsed[1:]))):
                    raise ValueError(f'Invalid operation timing for {trace_id}')
                elapsed = elapsed[:len(operations)]
            provenance[trace_id] = {'capture': capture, field: detail, 'source': row['source'], 'elapsed_ms': elapsed}
            traces.append(Trace(trace_id, label, row['role'], group, operations))
    return traces, provenance


def encode_traces(rows, bundle):
    vocabulary = bundle['vocabulary']
    if any(op not in vocabulary for row in rows for op in row.apis):
        raise ValueError('Fresh traces must share the seven-operation vocabulary of the original benchmark')
    return {row.trace_id: encode(row.apis, vocabulary, bundle['horizon']) for row in rows}


@torch.no_grad()
def gru_states(model, tokens, block_size):
    states = []
    for start in range(0, len(tokens), block_size):
        block = torch.tensor(tokens[start:start + block_size], dtype=torch.int64).unsqueeze(0)
        features, _ = model.gru(model.embedding(block))
        states.append(features[0])
    return torch.cat(states)


@torch.no_grad()
def train_readout_data(model, train, encoded, provenance, block_size):
    positions, endpoints = make_endpoints(train, encoded, 24, 771, 'early', 2.0)
    default_weights = defaultdict(dict)
    for trace_id, position, _, weight in endpoints:
        default_weights[trace_id][position - 1] = weight
    states, targets, weights, receipt = [], [], [], {}
    for trace in train:
        trace_id = trace.trace_id
        features = gru_states(model, encoded[trace_id], block_size)
        logits = model.head(features).flatten()
        positive = trace.label == RANSOMWARE
        # Preserve the original discriminative positive prefixes. The benign
        # hard examples are mined from the causal scores across each capture.
        search = logits[:EARLY_OBSERVATIONS] if positive else logits
        hard = torch.argsort(search, descending=True, stable=True)[:HARD_ENDPOINTS].tolist()
        rotation = provenance[trace_id].get('workload') == ROTATION
        share = 0.7 if rotation else 0.5
        influence = 2.0 if rotation else 1.0
        selected = {position: weight * (1 - share) for position, weight in default_weights[trace_id].items()}
        for position in hard:
            selected[position] = selected.get(position, 0.0) + share / len(hard)
        indices = sorted(selected)
        states.append(features[indices])
        targets.extend([float(positive)] * len(indices))
        weights.extend(selected[position] * influence for position in indices)
        receipt[trace_id] = {'sampled_endpoints': positions[trace_id], 'hard_endpoints': [p + 1 for p in hard]}

    x = torch.cat(states).double()
    y = torch.tensor(targets, dtype=torch.float64)
    w = torch.tensor(weights, dtype=torch.float64)
    for value in (0, 1):
        mask = y == value
        w[mask] *= 0.5 / w[mask].sum()
    return x, y, w, receipt


def refit_head(original, x, y, weights, penalty):
    head = copy.deepcopy(original.head).double()
    base_weight = head.weight.detach().clone()
    base_bias = head.bias.detach().clone()
    optimizer = torch.optim.LBFGS(head.parameters(), max_iter=120, line_search_fn='strong_wolfe')

    def objective():
        optimizer.zero_grad()
        logits = head(x).flatten()
        displacement = (head.weight - base_weight).square().sum() + (head.bias - base_bias).square().sum()
        loss = F.binary_cross_entropy_with_logits(logits, y, weight=weights, reduction='sum') + penalty * displacement
        if not loss.isfinite():
            raise ValueError('Nonfinite readout objective')
        loss.backward()
        return loss

    optimizer.step(objective)
    model = copy.deepcopy(original)
    model.head.load_state_dict(head.float().state_dict())
    return model.eval()


@torch.inference_mode()
def score(model, traces, encoded, block_size):
    return {trace.trace_id: list(score_blocks(model, encoded[trace.trace_id], block_size, DEVICE)) for trace in traces}


def calibrate(score_rows, eligible):
    return choose_threshold([max(score_rows[trace.trace_id]) for trace in eligible], ALPHA)


def outcome(score_rows, traces, provenance, threshold):
    rows = []
    labels = defaultdict(list)
    workloads = defaultdict(list)
    for trace in traces:
        metadata = provenance[trace.trace_id]
        scores = score_rows[trace.trace_id]
        alert = first_alert(scores, threshold)
        timing = metadata['elapsed_ms']
        row = {'trace_id': trace.trace_id, 'label': trace.label, 'capture': metadata['capture'],
               'first_event': alert, 'first_ms': timing[alert - 1] if timing is not None and alert is not None else None,
               'observed_events': len(scores)}
        if trace.label == BENIGN:
            row['workload'] = metadata['workload']
            workloads[row['workload']].append(row)
        else:
            row['family'] = metadata['family']
            labels[row['family']].append(row)
        rows.append(row)
    benign = [row for row in rows if row['label'] == BENIGN]
    positives = [row for row in rows if row['label'] == RANSOMWARE]
    return {
        'rows': rows,
        'benign': {'alerts': sum(r['first_event'] is not None for r in benign), 'total': len(benign)},
        'ransomware': summarize_positives(positives),
        'families': {family: summarize_positives(captures) for family, captures in labels.items()},
        'workloads': {workload: {'alerts': sum(r['first_event'] is not None for r in captures), 'total': len(captures)}
                      for workload, captures in workloads.items()},
    }


def selection_rank(result):
    positive = [row for row in result['rows'] if row['label'] == RANSOMWARE]
    positions = [row['first_event'] if row['first_event'] is not None else EARLY_OBSERVATIONS + 1 for row in positive]
    penalized_delay = sum(min(position, EARLY_OBSERVATIONS + 1) for position in positions)
    return (-result['ransomware']['early_alerts'], result['workloads'][ROTATION]['alerts'],
            result['benign']['alerts'], penalized_delay)


def keyed_tables(results, field):
    names = sorted(results[0][field])
    return [{'name': name, 'total': results[0][field][name]['total'],
             'models': {result['id']: result[field][name] for result in results}} for name in names]


def run(args):
    random.seed(123)
    torch.manual_seed(123)
    torch.use_deterministic_algorithms(True)
    torch.set_num_threads(args.cpu_threads)
    prior = json.loads((args.baseline / 'benchmark.json').read_bytes())
    prior_models = {item['id']: item for item in prior['models']}
    loaded = {name: load_bundle(args.baseline / 'models' / name / 'bundle.pt', DEVICE, prior_models[name]['bundle_sha256'])
              for name in ('counts', 'cnn', 'gru')}
    base, original_gru, original_digest = loaded['gru']
    horizon, block_size = base['horizon'], base['block_size']
    if any(bundle['horizon'] != horizon or bundle['block_size'] != block_size or bundle['vocabulary'] != base['vocabulary']
           for bundle, _, _ in loaded.values()):
        raise ValueError('The frozen model family has incompatible scorer invariants')
    old, data_hash = load_traces(args.benchmark_data)
    audit = json.loads(args.benchmark_audit.read_bytes())
    old_provenance, _, _, _ = validate_cohort(old, audit, data_hash, horizon)
    if data_hash != prior['evaluation']['data_sha256'] or digest(args.benchmark_audit) != prior['evaluation']['audit_sha256']:
        raise ValueError('Wrong prior benchmark data or provenance')

    benign, benign_provenance = read_fresh(args.benign, BENIGN, horizon, old, old_provenance)
    positive, positive_provenance = read_fresh(args.positive, RANSOMWARE, horizon, old + benign,
                                                {**old_provenance, **benign_provenance})
    provenance = {**old_provenance, **benign_provenance, **positive_provenance}
    train = sorted((trace for trace in old + benign if trace.role == 'train'), key=lambda trace: trace.trace_id)
    regression = [trace for trace in old if trace.role == 'test' and trace.label == RANSOMWARE]
    if {provenance[t.trace_id]['family'] for t in regression} != NAMED_FAMILIES:
        raise ValueError('Named-family regression must include DarkSide and Erebus')
    tuning = [trace for trace in benign if trace.role == 'tune']
    calibration = [trace for trace in benign if trace.role == 'calibrate']
    test = [trace for trace in benign if trace.role == 'test'] + positive
    for subset in (train, tuning, calibration, test):
        if not any(provenance[row.trace_id].get('workload') == ROTATION for row in subset):
            raise ValueError('Every benign role needs independently captured log rotation runs')
    if min(len(calibration), sum(trace.label == BENIGN for trace in test)) < 40:
        raise ValueError('Need at least 40 fresh calibration and 40 fresh test benign captures')
    encoded = encode_traces(train + regression + tuning + calibration + test, base)
    args.out.mkdir(parents=True, exist_ok=False)
    identity = {'benchmark_data_sha256': data_hash, 'benchmark_audit_sha256': digest(args.benchmark_audit),
                'benign_sha256': digest(args.benign), 'positive_sha256': digest(args.positive) if args.positive else None,
                'source_gru_sha256': original_digest, 'evaluator_sha256': digest(Path(__file__)),
                'pytorch': str(torch.__version__), 'block_size': block_size, 'horizon': horizon, 'cpu_threads': args.cpu_threads,
                'penalties': READOUT_PENALTIES}
    atomic_json(args.out / 'manifest.json', identity)
    x, y, weights, endpoints = train_readout_data(original_gru, train, encoded, provenance, block_size)
    atomic_json(args.out / 'readout-endpoints.json', endpoints)
    selected = None
    candidates = []
    for penalty in READOUT_PENALTIES:
        candidate = refit_head(original_gru, x, y, weights, penalty)
        scores = score(candidate, tuning + regression, encoded, block_size)
        threshold = calibrate(scores, tuning)
        diagnostics = outcome(scores, tuning + regression, provenance, threshold)
        rank = selection_rank(diagnostics)
        candidates.append({'penalty': penalty, 'rank': rank, 'tuning_threshold': threshold,
                           'tuning_rotation': diagnostics['workloads'][ROTATION],
                           'regression_families': diagnostics['families']})
        if selected is None or rank < selected[0]:
            selected = (rank, penalty, candidate)
    _, selected_penalty, refit = selected
    selection = {'penalty': selected_penalty, 'candidates': candidates,
                 'rule': 'Maximize previously evaluated named-family early alerts, then minimize tuning rotation alarms, '
                         'all tuning benign alarms, and named-family delay. Use preset penalty order for ties.'}
    atomic_json(args.out / 'selection.json', selection)
    print(f'Selected GRU readout penalty {selected_penalty} before fresh scoring.', flush=True)

    identifiers = ('counts', 'cnn', 'gru', 'gru_refit')
    models = [loaded[name][1] for name in identifiers[:-1]] + [refit]
    # All reported models get separate thresholds from the same fresh benign
    # capture maxima under the original 5% budget.
    results = []
    historical_gru = None
    for name, model in zip(identifiers, models):
        calibration_scores = score(model, calibration, encoded, block_size)
        threshold = calibrate(calibration_scores, calibration)
        atomic_json(args.out / f'{name}-calibration.json', threshold)
        print(f'Scoring {name} on fresh captures.', flush=True)
        scores = score(model, test + regression, encoded, block_size)
        fresh = outcome(scores, test, provenance, threshold)
        named = outcome(scores, regression, provenance, threshold)
        bundle = args.out / f'{name}.pt'
        atomic_torch(bundle, {**base, 'architecture': model.architecture, 'state_dict': model.state_dict(),
                             'identity': {**identity, 'architecture': model.architecture, 'variant': name},
                             'thresholds': [threshold]})
        result = {'id': name, 'calibration': {'alerts': threshold['alerts'], 'total': threshold['n'],
                                              'allowed': math.floor(ALPHA * threshold['n']),
                                              'threshold': threshold['tau'], 'mode': threshold['mode']},
                  'benign_test': fresh['benign'], 'ransomware_test': fresh['ransomware'],
                  'families': fresh['families'], 'benign_workloads': fresh['workloads'],
                  'regression_families': named['families'], 'bundle_sha256': digest(bundle)}
        results.append(result)
        atomic_json(args.out / f'{name}-alerts.json', {'fresh_test': fresh['rows'], 'regression': named['rows']})
        if name == 'gru':
            original_threshold = next(threshold for threshold in base['thresholds'] if threshold['alpha'] == ALPHA)
            historical = outcome(scores, test, provenance, original_threshold)
            historical_gru = {'benign_test': historical['benign'], 'log_rotation': historical['workloads'][ROTATION]}
            atomic_json(args.out / 'historical-threshold.json', {**historical, 'threshold': original_threshold})

    limitations = [
        'DarkSide and Erebus regression rows reuse the five previously evaluated CRIBA captures and influenced readout selection.',
        'Calibration and test workloads were recorded on a local Linux environment. Repeated workloads are not independent hosts.',
        'False-alarm rates are per capture. First alerts are relative to the retained successful-operation stream.',
    ]
    if not positive:
        limitations.append('No independent additional ransomware capture met the input contract. The fresh holdout is benign-only.')
    else:
        limitations.append('Fresh ransomware metrics use recorded telemetry from the sources shown below and may reflect collector differences.')
    counts = Counter(row.role for row in benign)
    report = {
        'schema': 'raneval-linux-benchmark-v1', 'title': 'GRU log-rotation refresh',
        'method': ('The selected readout refits on the original training split and new benign training captures. '
                   'The comparison freezes selection before fresh calibration or testing. Original model weights '
                   'receive new thresholds from the same calibration cohort.'),
        'provenance': [{'name': 'CRIBA', 'url': 'https://github.com/dsrhaslab/criba',
                        'detail': 'Original positive training captures and previously evaluated named-family regression.'},
                       {'name': 'Fresh Linux benign recordings', 'detail': 'Separated workload captures include log rotation.'}]
                      + ([{'name': 'Fresh recorded ransomware', 'detail': ', '.join(sorted({p['source'] for p in positive_provenance.values()}))}]
                         if positive else []),
        'limitations': limitations, 'budget': {'target_rate': ALPHA, 'unit': 'benign capture'},
        'early_event_horizon': EARLY_OBSERVATIONS,
        'models': [{k: v for k, v in result.items() if k not in ('families', 'regression_families', 'benign_workloads')}
                   for result in results],
        'families': keyed_tables(results, 'families'), 'regression_families': keyed_tables(results, 'regression_families'),
        'benign_workloads': keyed_tables(results, 'benign_workloads'),
        'historical_gru': historical_gru,
        'evaluation': {**identity, 'capture_counts': {**counts, 'train': len(train), 'test': len(test)},
                       'fresh_positive_captures': len(positive), 'regression_captures': len(regression),
                       'readout_penalty': selected_penalty},
    }
    atomic_json(args.out / 'benchmark.json', report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, default=Path('runs/linux-benchmark'))
    parser.add_argument('--benchmark-data', type=Path, default=Path('data/processed/linux-benchmark.jsonl'))
    parser.add_argument('--benchmark-audit', type=Path, default=Path('data/processed/linux-benchmark-audit.json'))
    parser.add_argument('--benign', type=Path, required=True)
    parser.add_argument('--positive', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--cpu-threads', type=int, default=1)
    args = parser.parse_args()
    if args.cpu_threads <= 0:
        parser.error('--cpu-threads must be positive')
    run(args)


if __name__ == '__main__':
    main()
