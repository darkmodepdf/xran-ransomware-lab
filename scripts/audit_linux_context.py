"""Verify a frozen Linux context comparison and audit collector sensitivity."""

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path

import torch

from benchmark_linux import BENIGN, RANSOMWARE
from benchmark_linux_context import BASELINES, CONTEXT_ID, read_contextual, rows_for, score_context
from refit_linux_gru import DEVICE, calibrate, encode_traces, outcome, score
from raneval.context_score import ContextStreamingScorer, load_context_bundle
from raneval.core import first_alert
from raneval.score import load_bundle
from raneval.train import atomic_json, digest


def coverage_by_operation(traces, events):
    result = defaultdict(lambda: defaultdict(Counter))
    for trace in traces:
        role = trace.role if trace.label == BENIGN else f'criba_{trace.role}'
        for event in events[trace.trace_id]:
            counts = result[role][event['op']]
            counts['events'] += 1
            for value in ('actor', 'file', 'directory', 'bytes_changed'):
                counts[value] += event.get(value) is not None
    return result


def audit(args):
    torch.set_num_threads(args.cpu_threads)
    torch.use_deterministic_algorithms(True)
    report_path = args.run / 'benchmark.json'
    report = json.loads(report_path.read_bytes())
    refs = {row['id']: row['bundle_sha256'] for row in report['models']}
    bundle, context_model, _ = load_context_bundle(args.run / f'{CONTEXT_ID}.pt', DEVICE, refs[CONTEXT_ID])
    horizon, block_size = bundle['horizon'], bundle['block_size']
    benign, benign_provenance, benign_events, benign_hash = read_contextual(args.benign, BENIGN, horizon)
    positive, positive_provenance, positive_events, positive_hash = read_contextual(args.positive, RANSOMWARE, horizon)
    if benign_hash != report['evaluation']['benign_sha256'] or positive_hash != report['evaluation']['positive_sha256']:
        raise ValueError('Capture checksums differ from the frozen report')
    provenance = {**benign_provenance, **positive_provenance}
    events = {**benign_events, **positive_events}
    calibration = [trace for trace in benign if trace.role == 'calibrate']
    test = [trace for trace in benign if trace.role == 'test']
    regression = [trace for trace in positive if trace.role == 'test']
    judged = calibration + test + regression
    encoded = encode_traces(judged, bundle)
    rows = rows_for(judged, events, block_size)

    verified = {}
    for name in (*BASELINES, CONTEXT_ID):
        if name == CONTEXT_ID:
            scores = score_context(context_model, judged, encoded, rows, block_size)
            current_bundle = bundle
        else:
            current_bundle, model, _ = load_bundle(args.run / f'{name}.pt', DEVICE, refs[name])
            scores = score(model, judged, encoded, block_size)
            if name == 'gru_refit' and (
                current_bundle['state_dict'].keys() != bundle['state_dict'].keys()
                or any(not weights.equal(bundle['state_dict'][name])
                       for name, weights in current_bundle['state_dict'].items())
            ):
                raise ValueError('Context model changed frozen token-only GRU weights')
        threshold = calibrate(scores, calibration)
        saved_threshold = json.loads((args.run / f'{name}-calibration.json').read_bytes())
        if [threshold] != current_bundle['thresholds'] or threshold != saved_threshold:
            raise ValueError(f'Saved calibration differs from frozen bundle re-score: {name}')
        alerts = {'fresh_test': outcome(scores, test, provenance, threshold)['rows'],
                  'regression': outcome(scores, regression, provenance, threshold)['rows']}
        if alerts != json.loads((args.run / f'{name}-alerts.json').read_bytes()):
            raise ValueError(f'Saved alert rows differ from frozen bundle re-score: {name}')
        verified[name] = {'calibration': len(calibration), 'fresh_test': len(test), 'regression': len(regression)}

    streaming_deltas, streaming_matches = {}, {}
    # Include both named families and the batch scorer's entire fresh test.
    for trace in test + regression:
        scorer = ContextStreamingScorer(bundle, context_model, DEVICE)
        streamed = [scorer.step(event) for event in events[trace.trace_id]]
        batched = scores[trace.trace_id]
        streaming_deltas[trace.trace_id] = max(abs(a - b) for a, b in zip(streamed, batched))
        streaming_matches[trace.trace_id] = first_alert(streamed, threshold) == first_alert(batched, threshold)

    # This secondary sensitivity masks both classes symmetrically. It measures
    # dependence on file identities without training or model selection.
    masked_events = {key: [{**event, 'file': None, 'directory': None} for event in value]
                     for key, value in events.items()}
    masked_scores = score_context(context_model, judged, encoded, rows_for(judged, masked_events, block_size), block_size)
    masked_threshold = calibrate(masked_scores, calibration)
    masked_test = outcome(masked_scores, test, provenance, masked_threshold)
    masked_known = outcome(masked_scores, regression, provenance, masked_threshold)
    atomic_json(args.run / 'audit.json', {
        'benchmark_sha256': digest(report_path), 'verification': verified,
        'coverage_by_operation': coverage_by_operation(benign + positive, events),
        'streaming': {'captures': len(streaming_matches), 'matched_first_alerts': sum(streaming_matches.values()),
                      'changed_alerts': [key for key, matched in streaming_matches.items() if not matched],
                      'max_score_delta': max(streaming_deltas.values())},
        'masked_file_and_directory': {'calibration': masked_threshold, 'benign_test': masked_test['benign'],
                                      'benign_workloads': masked_test['workloads'],
                                      'known_ransomware': masked_known['ransomware'],
                                      'known_families': masked_known['families']},
    })
    print(f'Re-scored {len(judged)} captures across all {len(verified)} frozen models. '
          f'Context streaming matched {sum(streaming_matches.values())}/{len(streaming_matches)} alert positions.', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, default=Path('runs/linux-gru-context'))
    parser.add_argument('--benign', type=Path, default=Path('data/processed/linux-context-benign.jsonl'))
    parser.add_argument('--positive', type=Path, default=Path('data/processed/linux-gru-context-criba.jsonl'))
    parser.add_argument('--cpu-threads', type=int, default=1)
    args = parser.parse_args()
    if args.cpu_threads <= 0:
        parser.error('--cpu-threads must be positive')
    audit(args)


if __name__ == '__main__':
    main()
