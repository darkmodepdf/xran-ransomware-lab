"""Fit and compare expanded EN2025 detectors on a fresh, shared test partition."""

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import subprocess
import sys
import tempfile
import time

import torch

from .core import choose_threshold, encode, first_alert, load_traces, score_blocks
from .score import load_bundle
from .train import atomic_json, atomic_torch, digest


ARCHITECTURES = ('cnn', 'gru')
ALPHAS = (0.02, 0.01, 0.05)
HORIZON = 2048
VARIANTS = {
    'refit': {'block_size': 256, 'endpoint_policy': 'standard', 'early_loss_weight': 1.0},
    'early': {'block_size': 256, 'endpoint_policy': 'early', 'early_loss_weight': 2.0},
    'early_long': {'block_size': 1024, 'endpoint_policy': 'early', 'early_loss_weight': 2.0},
}
LABELS = ('RANSOMWARE', 'BENIGN', 'OTHER_MALWARE')
EARLY_POINTS = (120, 256, 512)
BOOTSTRAPS = 2000


def observations_by_role(traces):
    roles = {}
    for trace in traces:
        roles.setdefault(trace.role, []).append(trace)
    for role, labels in {
        'train': LABELS, 'tune': LABELS, 'calibrate': ('BENIGN',), 'test': LABELS,
    }.items():
        counts = Counter(trace.label for trace in roles.get(role, ()) if trace.apis)
        if any(counts[label] == 0 for label in labels):
            raise ValueError(f'Missing required nonempty class in {role}: {counts}')
    return roles


def development_copy(source, destination):
    with source.open('rb') as original, destination.open('xb') as new:
        for line in original:
            if line.strip() and json.loads(line)['role'] in ('train', 'tune'):
                new.write(line)


def scores_for(run, traces, device):
    frozen = json.loads((run / 'frozen.json').read_bytes())
    bundle, model, checksum = load_bundle(run / 'bundle.pt', device, frozen['bundle_sha256'])
    for trace in traces:
        tokens = encode(trace.apis, bundle['vocabulary'], min(bundle['horizon'] or HORIZON, HORIZON))
        scores = list(score_blocks(model, tokens, bundle['block_size'], device))
        yield trace, scores
    del model, bundle


def assess(run, reference, evaluation, device, *, alphas=ALPHAS, frozen_thresholds=()):
    maxima = [max(scores) for _, scores in scores_for(run, reference, device) if scores]
    thresholds = {f'cal_{alpha:g}': choose_threshold(maxima, alpha) for alpha in alphas}
    for threshold in frozen_thresholds:
        thresholds[f'original_{threshold["alpha"]:g}'] = threshold
    records = {key: [] for key in thresholds}
    for trace, scores in scores_for(run, evaluation, device):
        if not scores:
            continue
        for key, threshold in thresholds.items():
            alert = first_alert(scores, threshold)
            records[key].append({'trace_id': trace.trace_id, 'group_id': trace.group_id, 'label': trace.label,
                                 'length': len(scores), 'first_observation': alert})
    return thresholds, records


def summarize(records):
    result = {}
    for label in LABELS:
        rows = [row for row in records if row['label'] == label]
        n = len(rows)
        indices = [r['first_observation'] for r in rows if r['first_observation'] is not None]
        result[label] = {'n': n, 'alerts': len(indices),
                         'alert_rate': len(indices) / n if n else None,
                         **{f'by_{p}': sum(index <= p for index in indices) for p in EARLY_POINTS}}
    return result


def choose_candidate(tune):
    refit = tune['refit']

    def key(item):
        variant, result = item
        excess = [max(0, result[label]['alerts'] - refit[label]['alerts']) for label in LABELS[1:]]
        # Prefer candidates that stayed within both reference alarm counts on tuning.
        return (sum(excess), -result['RANSOMWARE']['by_120'], -result['RANSOMWARE']['alerts'],
                result['BENIGN']['alerts'], result['OTHER_MALWARE']['alerts'], VARIANTS[variant]['block_size'], variant)

    return min(((v, value) for v, value in tune.items() if v != 'refit'), key=key)[0]


def paired_difference(candidate, baseline, label, *, cutoff=None):
    baseline_ids = {row['trace_id']: row for row in baseline if row['label'] == label}
    candidate_ids = {row['trace_id']: row for row in candidate if row['label'] == label}
    if not baseline_ids or baseline_ids.keys() != candidate_ids.keys():
        raise ValueError(f'Paired metric needs the same nonempty {label} cohort')
    groups = {}

    def caught(row):
        position = row['first_observation']
        return int(position is not None and (cutoff is None or position <= cutoff))

    for trace_id, previous in baseline_ids.items():
        current = candidate_ids[trace_id]
        if (previous['group_id'], previous['length']) != (current['group_id'], current['length']):
            raise ValueError('Paired score has inconsistent trace provenance or horizon')
        values = groups.setdefault(previous['group_id'], [0, 0])
        values[0] += caught(current) - caught(previous)
        values[1] += 1
    pairs = [groups[key] for key in sorted(groups)]
    delta = sum(value for value, _ in pairs)
    total = sum(n for _, n in pairs)
    rng = random.Random(22419)
    draws = []
    for _ in range(BOOTSTRAPS):
        sample = rng.choices(pairs, k=len(pairs))
        draws.append(sum(value for value, _ in sample) / sum(n for _, n in sample))
    draws.sort()
    return {'delta_count': delta, 'delta_rate': delta / total, 'n': total, 'groups': len(pairs),
            'paired_group_bootstrap_95pct': [draws[int(0.025 * BOOTSTRAPS)], draws[int(0.975 * BOOTSTRAPS) - 1]]}


def compare(candidate, comparator):
    result = {
        'ransomware_by_120': paired_difference(candidate, comparator, 'RANSOMWARE', cutoff=120),
        'ransomware_anytime': paired_difference(candidate, comparator, 'RANSOMWARE'),
        'benign_alarms': paired_difference(candidate, comparator, 'BENIGN'),
        'other_malware_alarms': paired_difference(candidate, comparator, 'OTHER_MALWARE'),
    }
    result['empirical_target_met'] = (result['ransomware_by_120']['delta_count'] > 0
                                      and result['ransomware_anytime']['delta_count'] >= 0
                                      and result['benign_alarms']['delta_count'] <= 0
                                      and result['other_malware_alarms']['delta_count'] <= 0)
    return result


def load_pilot_runs(root):
    for architecture in ARCHITECTURES:
        path = root / architecture
        manifest = json.loads((path / 'frozen.json').read_bytes())
        if manifest['identity']['config']['architecture'] != architecture:
            raise ValueError('Unexpected prior model architecture')
        if digest(path / 'bundle.pt') != manifest['bundle_sha256']:
            raise ValueError('Prior pilot bundle checksum mismatch')
        yield architecture, path, manifest


def prepare_fit(development, output, arch, variant, config, args, device, elapsed):
    command = [sys.executable, '-m', 'raneval.train', '--data', str(development), '--run-dir', str(output),
               '--architecture', arch, '--device', device.type, '--epochs', str(args.epochs),
               '--block-size', str(config['block_size']), '--horizon', str(HORIZON), '--seed', str(args.seed),
               '--batch-size', '32', '--endpoint-policy', config['endpoint_policy'],
               '--early-loss-weight', str(config['early_loss_weight']), '--target-fpr', str(ALPHAS[0]),
               '--tune-objective', 'early120', '--skip-test', '--checkpoint-seconds', '600', '--cpu-threads', '2']
    if args.budget_minutes:
        remaining = args.budget_minutes - elapsed() / 60
        if remaining <= args.reserve_minutes:
            return False
        command.extend(['--budget-minutes', str(remaining), '--reserve-minutes', str(args.reserve_minutes)])
    if arch == 'cnn' and variant == 'refit':
        subprocess.run([*command, '--stop-after-steps', '2'], check=True)
        checkpoint = json.loads((output / 'recovery.json').read_bytes())
        if checkpoint['step'] != 2 or (output / 'metrics.json').exists():
            raise RuntimeError('Initial recovery smoke did not interrupt at step 2')
        command.append('--resume')
    subprocess.run(command, check=True)
    return (output / 'metrics.json').is_file()


def export_calibrated(run, result, output):
    output.mkdir()
    bundle = torch.load(run / 'bundle.pt', map_location='cpu', weights_only=True)
    bundle['thresholds'] = [result[f'cal_{alpha:g}'] for alpha in ALPHAS]
    atomic_torch(output / 'bundle.pt', bundle)
    atomic_json(output / 'frozen.json', {'bundle_sha256': digest(output / 'bundle.pt'),
                                        'thresholds': bundle['thresholds'], 'identity': bundle['identity']})


def run_comparison(args):
    started = time.monotonic()

    def elapsed():
        return time.monotonic() - started

    os.environ.setdefault('CUBLAS_WORKSPACE_CONFIG', ':4096:8')
    torch.set_num_threads(2)
    torch.use_deterministic_algorithms(True)
    runtime = 'cuda' if args.runtime == 'auto' else args.runtime
    if runtime == 'cuda' and not torch.cuda.is_available():
        raise RuntimeError('Kaggle CUDA runtime is required for this run')
    device = torch.device(runtime)
    traces, data_hash = load_traces(args.data)
    roles = observations_by_role(traces)
    pilots = {name: (path, manifest) for name, path, manifest in load_pilot_runs(args.old_runs)}
    args.out.mkdir(parents=True, exist_ok=False)
    fits = args.out / 'fits'
    fits.mkdir()
    plan = {'data_sha256': data_hash, 'horizon': HORIZON, 'precommitted_grid': VARIANTS,
            'primary_alpha': ALPHAS[0], 'secondary_alphas': list(ALPHAS[1:]), 'seed': args.seed,
            'epochs': args.epochs, 'early_points': list(EARLY_POINTS), 'device': runtime,
            'code_sha256': {file.name: digest(file) for file in Path(__file__).parent.glob('*.py')},
            'gpu_name': torch.cuda.get_device_name(0) if runtime == 'cuda' else None,
            'platform': platform.platform(), 'torch': str(torch.__version__),
            'roles': {role: dict(Counter(t.label for t in rows)) for role, rows in roles.items()},
            'prior_bundle_sha256': {name: manifest['bundle_sha256'] for name, (_, manifest) in pilots.items()},
            'selection': 'Minimize excess benign and other-malware tuning alarms versus refit at 2% nominal, then maximize recall by 120 and anytime recall.',
            'target': 'More catches by 120, at least as many anytime, with no extra benign or other-malware alarms on the fresh test.'}
    atomic_json(args.out / 'protocol.json', plan)
    selected = {}
    tune = {}
    with tempfile.TemporaryDirectory(prefix='raneval-expansion-') as scratch:
        development = Path(scratch) / 'development.jsonl'
        development_copy(args.data, development)
        for arch in ARCHITECTURES:
            tune[arch] = {}
            for name, config in VARIANTS.items():
                fit = fits / f'{arch}-{name}'
                if not prepare_fit(development, fit, arch, name, config, args, device, elapsed):
                    atomic_json(args.out / 'incomplete.json', {'reason': 'fit budget exhausted', 'fit': fit.name, 'elapsed_seconds': elapsed()})
                    return
                _, rows = assess(fit, [row for row in roles['tune'] if row.label == 'BENIGN'],
                                 roles['tune'], device, alphas=ALPHAS[:1])
                tune[arch][name] = summarize(rows['cal_0.02'])
            selected[arch] = choose_candidate(tune[arch])
    selection = {'selected': selected, 'tune': tune, 'data_sha256': data_hash}
    atomic_json(args.out / 'selection.json', selection)
    selection_digest = digest(args.out / 'selection.json')
    frozen_root = args.out / 'calibrated-bundles'
    frozen_root.mkdir()
    report = {'protocol': plan, 'selection_sha256': selection_digest,
              'candidate_names': selected, 'results': {}, 'comparisons': {}}
    per_trace = args.out / 'paired-test-alerts.jsonl'
    with per_trace.open('x', encoding='utf-8') as stream:
        for arch in ARCHITECTURES:
            pilot_dir, manifest = pilots[arch]
            runs = {'pilot': pilot_dir, 'refit': fits / f'{arch}-refit', 'candidate': fits / f'{arch}-{selected[arch]}'}
            primary = {}
            report['results'][arch] = {}
            for key, run in runs.items():
                original = [t for t in manifest['thresholds'] if t['alpha'] == 0.05] if key == 'pilot' else []
                thresholds, grouped = assess(run, roles['calibrate'], roles['test'], device, frozen_thresholds=original)
                primary[key] = grouped['cal_0.02']
                report['results'][arch][key] = {'thresholds': thresholds,
                                                'test': {k: summarize(v) for k, v in grouped.items()}}
                if key in ('refit', 'candidate'):
                    export_calibrated(run, thresholds, frozen_root / f'{arch}-{key}')
                for setting, records in grouped.items():
                    for record in records:
                        stream.write(json.dumps({'architecture': arch, 'model': key, 'setting': setting, **record}, allow_nan=False) + '\n')
            report['comparisons'][arch] = {f'candidate_vs_{key}': compare(primary['candidate'], primary[key]) for key in ('pilot', 'refit')}
    report['elapsed_seconds'] = elapsed()
    report['restart_smoke_passed'] = True
    report['paired_alerts_sha256'] = digest(per_trace)
    atomic_json(args.out / 'comparison.json', report)
    print(json.dumps({'selected': selected, 'comparisons': report['comparisons'], 'seconds': report['elapsed_seconds']}, indent=2), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', type=Path, required=True)
    parser.add_argument('--old-runs', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--runtime', choices=('cpu', 'cuda', 'auto'), default='auto')
    parser.add_argument('--budget-minutes', type=float, default=0, help='Zero disables the fit time cap for local smoke tests.')
    parser.add_argument('--reserve-minutes', type=float, default=30)
    parser.add_argument('--seed', type=int, default=123)
    parser.add_argument('--epochs', type=int, default=3)
    args = parser.parse_args()
    if args.epochs < 1 or args.seed < 0 or min(args.budget_minutes, args.reserve_minutes) < 0:
        parser.error('Invalid training arguments')
    if args.budget_minutes and args.budget_minutes <= args.reserve_minutes:
        parser.error('Runtime budget must exceed the export reserve')
    run_comparison(args)


if __name__ == '__main__':
    main()
