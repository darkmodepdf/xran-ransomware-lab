"""Validate the downloaded expanded-pilot artifacts and print paired headline counts."""

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path


MODELS = ('cnn', 'gru')


def load(path):
    return json.loads(path.read_bytes())


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def rows(path):
    with path.open('rb') as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)


def verify(data, root, *, require_cuda):
    protocol = load(root / 'protocol.json')
    choice = load(root / 'selection.json')
    comparison = load(root / 'comparison.json')
    assert comparison['protocol'] == protocol
    assert comparison['candidate_names'] == choice['selected']
    assert comparison['selection_sha256'] == sha256(root / 'selection.json')
    assert protocol['data_sha256'] == choice['data_sha256'] == sha256(data)
    assert comparison['restart_smoke_passed']
    if require_cuda:
        assert protocol['device'] == 'cuda' and protocol['gpu_name'], 'Expected CUDA evidence'
    reference = {row['trace_id']: row for row in rows(data) if row['role'] == 'test' and row['apis']}
    alert_path = root / 'paired-test-alerts.jsonl'
    assert comparison['paired_alerts_sha256'] == sha256(alert_path)
    indexed = defaultdict(dict)
    for row in rows(alert_path):
        src = reference[row['trace_id']]
        assert (row['group_id'], row['label']) == (src['group_id'], src['label'])
        assert row['length'] == min(len(src['apis']), protocol['horizon'])
        assert row['first_observation'] is None or 1 <= row['first_observation'] <= row['length']
        tag = (row['architecture'], row['model'], row['setting'])
        assert row['trace_id'] not in indexed[tag]
        indexed[tag][row['trace_id']] = row
    used_tags = set()
    totals = Counter(row['label'] for row in reference.values())
    print(f"Verified runtime: {protocol['device']}, GPU: {protocol['gpu_name']}, test: {dict(totals)}")
    for arch in MODELS:
        primary_by_model = {}
        for name, config in protocol['precommitted_grid'].items():
            fit = root / 'fits' / f'{arch}-{name}'
            meta = load(fit / 'metrics.json')
            identity = meta['identity']
            assert identity['config']['architecture'] == arch and identity['config']['device'] == protocol['device']
            for field, value in config.items():
                assert identity['config'][field] == value
            assert identity['config']['epochs'] == protocol['epochs']
            assert identity['config']['skip_test'] and 'test' not in meta
            assert sha256(fit / 'bundle.pt') == meta['bundle_sha256']
            recovery = load(fit / 'recovery.json')
            assert sha256(fit / f"recovery-{recovery['slot']}.pt") == recovery['sha256']
        for key in ('pilot', 'refit', 'candidate'):
            entry = comparison['results'][arch][key]
            if key != 'pilot':
                exported = root / 'calibrated-bundles' / f'{arch}-{key}'
                frozen = load(exported / 'frozen.json')
                assert frozen['bundle_sha256'] == sha256(exported / 'bundle.pt')
                assert all(t == entry['thresholds'][f'cal_{t["alpha"]:g}'] for t in frozen['thresholds'])
            for setting, strata in entry['test'].items():
                used_tags.add((arch, key, setting))
                by_id = indexed[arch, key, setting]
                assert by_id.keys() == reference.keys()
                for label, count in totals.items():
                    positions = [row['first_observation'] for row in by_id.values()
                                 if row['label'] == label and row['first_observation'] is not None]
                    assert strata[label]['n'] == count and strata[label]['alerts'] == len(positions)
                    for point in protocol['early_points']:
                        assert strata[label][f'by_{point}'] == sum(position <= point for position in positions)
            primary = entry['test'][f'cal_{protocol["primary_alpha"]:g}']
            primary_by_model[key] = primary
            positive = primary['RANSOMWARE']
            print(f'{arch} {key:9s} by 120 {positive["by_120"]}/{positive["n"]}, '
                  f'any {positive["alerts"]}/{positive["n"]}, '
                  f'benign {primary["BENIGN"]["alerts"]}/{totals["BENIGN"]}, '
                  f'other {primary["OTHER_MALWARE"]["alerts"]}/{totals["OTHER_MALWARE"]}')
        candidate = primary_by_model['candidate']
        for name in ('pilot', 'refit'):
            comparator = primary_by_model[name]
            reported = comparison['comparisons'][arch][f'candidate_vs_{name}']
            measured = {}
            for metric, label, column in (
                ('ransomware_by_120', 'RANSOMWARE', 'by_120'),
                ('ransomware_anytime', 'RANSOMWARE', 'alerts'),
                ('benign_alarms', 'BENIGN', 'alerts'),
                ('other_malware_alarms', 'OTHER_MALWARE', 'alerts'),
            ):
                delta = candidate[label][column] - comparator[label][column]
                assert reported[metric]['delta_count'] == delta and reported[metric]['n'] == totals[label]
                measured[metric] = delta
            met = (measured['ransomware_by_120'] > 0 and measured['ransomware_anytime'] >= 0
                   and measured['benign_alarms'] <= 0 and measured['other_malware_alarms'] <= 0)
            assert reported['empirical_target_met'] == met
    assert used_tags == indexed.keys()
    return comparison


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', type=Path, required=True)
    parser.add_argument('--run', type=Path, required=True, help='Directory containing comparison.json')
    parser.add_argument('--allow-cpu-smoke', action='store_true')
    args = parser.parse_args()
    verify(args.data, args.run, require_cuda=not args.allow_cpu_smoke)


if __name__ == '__main__':
    main()
