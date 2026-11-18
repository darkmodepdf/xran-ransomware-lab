"""Verify the Linux Kaggle pilot and stage immutable CPU inference and replay inputs."""

import argparse
from collections import defaultdict
import hashlib
import json
import math
from pathlib import Path
import tempfile

import numpy as np
import onnxruntime as ort
import torch
from torch.nn import functional as F

from raneval.core import EARLY_OBSERVATIONS, encode, first_alert, load_traces, score_blocks
from raneval.score import StreamingScorer, load_bundle


ALPHA = 0.05
MAX_DEMO_EVENTS = 384


class PrefixEndpoint(torch.nn.Module):
    """Export the final position of the causal block prefix."""

    def __init__(self, model):
        super().__init__()
        self.model = model

    def forward(self, tokens):
        model = self.model
        embedded = model.embedding(tokens)
        if model.architecture == 'cnn':
            channels = embedded.transpose(1, 2)
            first = F.relu(model.conv1(F.pad(channels, (4, 0))))
            second = F.relu(model.conv2(F.pad(first, (4, 0))))
            return model.head(second.amax(dim=-1))
        states, _ = model.gru(embedded)
        return model.head(states[:, -1, :])


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8'))


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n', encoding='utf-8')


def verify_runs(root, traces, data_sha256, provenance):
    completed = read_json(root / 'pilot-complete.json')
    env = read_json(root / 'environment.json')
    if (not completed['cuda_used'] or not completed['restart_smoke_passed'] or not env['gpu']
            or env['purpose'] != 'Linux eBPF pilot' or env['input_sha256']['traces.jsonl'] != data_sha256):
        raise ValueError('Expected a completed Linux GPU pilot for this cohort')
    if set(completed['architecture']) != {'cnn', 'gru'}:
        raise ValueError('Expected both candidate architectures in the completed GPU run')
    experiment = {}
    for architecture in completed['architecture']:
        directory = root / architecture
        for name, expected in completed['artifact_sha256'][architecture].items():
            if Path(name).name != name or digest(directory / name) != expected:
                raise ValueError(f'GPU artifact checksum mismatch for {architecture}/{name}')
        frozen = read_json(directory / 'frozen.json')
        metrics = read_json(directory / 'metrics.json')
        recovery = read_json(directory / 'recovery.json')
        if (digest(directory / 'bundle.pt') != frozen['bundle_sha256']
                or digest(directory / f"recovery-{recovery['slot']}.pt") != recovery['sha256']
                or frozen['identity']['data_sha256'] != data_sha256):
            raise ValueError(f'Bundle, checkpoint or cohort identity mismatch for {architecture}')
        expected_traces = {trace.trace_id: trace for trace in traces if trace.role == 'test'}
        observed = defaultdict(list)
        with (directory / 'test_alerts.jsonl').open(encoding='utf-8') as stream:
            for line in stream:
                row = json.loads(line)
                if row['alpha'] != ALPHA:
                    continue
                trace = expected_traces.pop(row['trace_id'])
                horizon = frozen['identity']['config']['horizon'] or len(trace.apis)
                if (row['label'] != trace.label or row['group_id'] != trace.group_id
                        or row['observed_horizon'] != min(horizon, len(trace.apis))):
                    raise ValueError(f'Test trace identity mismatch for {trace.trace_id}')
                observed[trace.label].append(row)
        if expected_traces:
            raise ValueError(f'Missing test alert rows for {architecture}')
        strata = next(summary['strata'] for summary in metrics['test'] if summary['alpha'] == ALPHA)
        evidence = {}
        for label in ('BENIGN', 'RANSOMWARE'):
            rows = [row for row in observed[label] if row['observed_horizon']]
            alerts = [row for row in rows if row['first_observation'] is not None]
            if (len(rows), len(alerts)) != (strata[label]['n'], strata[label]['alerts']):
                raise ValueError(f'Reported test totals mismatch for {architecture}/{label}')
            captures = {provenance[row['trace_id']]['capture'] for row in rows}
            alert_captures = {provenance[row['trace_id']]['capture'] for row in alerts}
            evidence[label] = {'processes': len(rows), 'alerts': len(alerts),
                               'by_120': sum(row['first_observation'] <= EARLY_OBSERVATIONS for row in alerts),
                               'shorter_than_120': sum(row['observed_horizon'] < EARLY_OBSERVATIONS for row in rows),
                               'captures': len(captures), 'captures_with_alert': len(alert_captures)}
        experiment[architecture] = {'tune': metrics['tune'], 'thresholds': frozen['thresholds'],
                                    'test': evidence, 'optimizer_steps': recovery['step']}
    return {'hardware': env['gpu'], 'elapsed_seconds': completed['elapsed_seconds'],
            'nominal_alpha': ALPHA, 'models': experiment}


def export_endpoint(model, path):
    torch.onnx.export(
        PrefixEndpoint(model).eval(), (torch.tensor([[2, 2, 2]], dtype=torch.int64),), path,
        input_names=['tokens'], output_names=['logits'],
        dynamic_axes={'tokens': {1: 'sequence_length'}}, opset_version=17, dynamo=False,
    )
    options = ort.SessionOptions()
    options.intra_op_num_threads = 1
    options.inter_op_num_threads = 1
    return ort.InferenceSession(str(path), sess_options=options, providers=['CPUExecutionProvider'])


def check_parity(apis, bundle, model, session, threshold):
    device = torch.device('cpu')
    streaming = StreamingScorer(bundle, model, device)
    block = []
    cpu, onnx = [], []
    for index, token in enumerate(encode(apis, bundle['vocabulary'], bundle['horizon'])):
        if index % bundle['block_size'] == 0:
            block.clear()
        block.append(token)
        logits = session.run(['logits'], {'tokens': np.asarray([block], dtype=np.int64)})[0]
        if logits.shape != (1, 1) or not np.isfinite(logits).all():
            raise ValueError('Unexpected endpoint output from ONNX')
        logit = float(logits[0, 0])
        # Stable sigmoid in the same precision used by the PyTorch scorer.
        exponent = math.exp(-abs(logit))
        onnx.append((1 if logit >= 0 else exponent) / (1 + exponent))
        cpu.append(streaming.step(apis[index]))
    error = max((abs(left - right) for left, right in zip(cpu, onnx)), default=0.0)
    alert = first_alert(cpu, threshold)
    if error > 2e-6 or alert != first_alert(onnx, threshold):
        raise ValueError(f'PyTorch and ONNX replay differ at the frozen threshold (max error {error})')
    return {'events': len(cpu), 'max_score_error': error, 'first_alert_observation': alert}


def fixture_key(trace):
    return hashlib.sha256(f'linux-dashboard-v1:{trace.trace_id}'.encode()).digest(), trace.trace_id


def stage(data, audit_path, runs, output):
    torch.set_num_threads(1)
    traces, data_sha256 = load_traces(data)
    audit = read_json(audit_path)
    provenance = audit['trace_provenance']
    if set(provenance) != {trace.trace_id for trace in traces}:
        raise ValueError('Cohort provenance does not match the prepared trace identities')
    result = verify_runs(runs, traces, data_sha256, provenance)
    architecture = max(
        result['models'], key=lambda name: (result['models'][name]['tune']['early120'],
                                          result['models'][name]['tune']['grid_mean'], name == 'cnn'),
    )
    result['selected_architecture'] = architecture
    result['selection_rule'] = 'Tuning recall by 120, then tuning earliness, then CNN on a tie'
    folder = runs / architecture
    frozen = read_json(folder / 'frozen.json')
    bundle, model, _ = load_bundle(folder / 'bundle.pt', torch.device('cpu'), frozen['bundle_sha256'])
    threshold = next(row for row in bundle['thresholds'] if row['alpha'] == ALPHA)
    positive = [trace for trace in traces if trace.label == 'RANSOMWARE' and trace.role == 'tune']
    clean = [trace for trace in traces if trace.label == 'BENIGN' and trace.role == 'test'
             and 'benign' in provenance[trace.trace_id]['capture'].lower()]
    fixed_positive = min(positive, key=fixture_key)
    fixed_clean = min((trace for trace in clean if len(trace.apis) >= EARLY_OBSERVATIONS), key=fixture_key,
                      default=min(clean, key=fixture_key))
    fixed = {'ransomware': fixed_positive, 'benign': fixed_clean}
    horizon = min(bundle['horizon'] or MAX_DEMO_EVENTS, MAX_DEMO_EVENTS)

    def alert_in_preview(trace):
        tokens = encode(trace.apis, bundle['vocabulary'], horizon)
        return first_alert(score_blocks(model, tokens, bundle['block_size'], 'cpu'), threshold)

    fixed_alert = alert_in_preview(fixed_positive)
    if fixed_alert is None or fixed_alert > EARLY_OBSERVATIONS:
        options = []
        for trace in traces:
            if trace.label == 'RANSOMWARE' and trace.role in ('tune', 'train') and trace != fixed_positive:
                alert = alert_in_preview(trace)
                if alert is not None and alert <= EARLY_OBSERVATIONS and alert < len(trace.apis[:horizon]):
                    options.append((trace.role != 'tune', alert, fixture_key(trace), trace))
        if options:
            fixed['illustrative'] = min(options)[-1]

    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(output)
    with tempfile.TemporaryDirectory(dir=output.parent, prefix='.linux-stage-') as temporary:
        stage_dir = Path(temporary)
        graph = stage_dir / 'model.onnx'
        session = export_endpoint(model, graph)
        vocabulary = sorted(bundle['vocabulary'])
        reset_check = tuple(vocabulary[i % len(vocabulary)] for i in range(bundle['block_size'] + 2))
        result['reset_boundary_parity'] = check_parity(reset_check, bundle, model, session, threshold)
        manifest = {'source': 'ebpfangel recorded Linux events', 'alpha': ALPHA, 'fixtures': {}}
        result['fixtures'] = {}
        for name, trace in fixed.items():
            apis = trace.apis[:horizon]
            path = stage_dir / f'{name}.jsonl'
            path.write_bytes(''.join(json.dumps(token) + '\n' for token in apis).encode('utf-8'))
            checked = check_parity(apis, bundle, model, session, threshold)
            manifest['fixtures'][name] = {
                'trace_id': trace.trace_id, 'role': trace.role, 'family': provenance[trace.trace_id]['family'],
                'capture': provenance[trace.trace_id]['capture'], 'sha256': digest(path),
                'observations': len(apis), 'first_alert_observation': checked['first_alert_observation'],
                'selection': ('Development example selected for an early alert at the frozen threshold'
                              if name == 'illustrative' else 'Fixed trace ID ordering, independent of scores'),
            }
            result['fixtures'][name] = checked
        frozen.update({key: bundle[key] for key in ('architecture', 'vocabulary', 'block_size', 'horizon')})
        frozen['onnx_sha256'] = digest(graph)
        write_json(stage_dir / 'manifest.json', manifest)
        write_json(stage_dir / 'frozen.json', frozen)
        write_json(stage_dir / 'verification.json', result)
        stage_dir.rename(output)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ('data', 'audit', 'runs', 'out'):
        parser.add_argument(f'--{argument}', type=Path, required=True)
    args = parser.parse_args()
    result = stage(args.data, args.audit, args.runs, args.out)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
