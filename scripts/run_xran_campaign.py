"""Run prespecified independent XRan fits on the available Kaggle GPUs."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import time

import torch

from raneval.train_xran import candidate_rank
from raneval.xran_models import atomic_json, digest


def run(args):
    started = time.monotonic()
    protocol_path, data, out = Path(args.protocol), Path(args.data_dir), Path(args.out)
    protocol = json.loads(protocol_path.read_bytes())
    if protocol['schema'] != 'xran-campaign-protocol-v1':
        raise ValueError('Unsupported campaign protocol')
    if not torch.cuda.is_available():
        raise RuntimeError('This campaign requires actual Kaggle GPU training')
    out.mkdir(parents=True, exist_ok=False)
    atomic_json(out / 'protocol.json', protocol)
    slots = queue.Queue()
    for index in range(min(2, torch.cuda.device_count())):
        slots.put(index)
    deadline = started + args.budget_minutes * 60 - args.elapsed_before_seconds
    initial = {'schema': 'xran-campaign-state-v1', 'status': 'training',
               'protocol_sha256': digest(protocol_path),
               'started_at': datetime.now(timezone.utc).isoformat(),
               'gpu_count': slots.qsize(), 'gpu_policy': 'one independent fit per GPU, no DDP',
               'test_outcomes_opened': False}
    atomic_json(out / 'campaign-state.json', initial)

    def fit(job, smoke=False):
        gpu = slots.get()
        try:
            folder = out / job['run']
            folder.parent.mkdir(parents=True, exist_ok=True)
            remaining = (deadline - time.monotonic()) / 60
            if remaining <= args.reserve_minutes + 2:
                raise RuntimeError('Insufficient campaign time for another fit and export reserve')
            dataset = data / 'api-component' if job.get('data_variant') == 'api-component' else data
            command = [sys.executable, '-m', 'raneval.train_xran', '--data-dir', str(dataset),
                       '--out', str(folder), '--model', job['model'], '--view', job['view'],
                       '--seed', str(job['seed']), '--epochs', str(protocol['epochs']),
                       '--batch-size', str(protocol['batch_size']), '--lr', str(job['lr']),
                       '--weight-decay', str(protocol['weight_decay']), '--device', 'cuda:0',
                       '--threads', '2', '--budget-minutes', str(remaining),
                       '--reserve-minutes', str(args.reserve_minutes), '--config-id', job['config_id']]
            env = dict(os.environ, CUDA_VISIBLE_DEVICES=str(gpu), CUBLAS_WORKSPACE_CONFIG=':4096:8',
                       OMP_NUM_THREADS='2', MKL_NUM_THREADS='2')
            logfile = out / (job['run'].replace('/', '-') + '.log')
            print(json.dumps({'event': 'fit_start', 'job': job, 'gpu': gpu}), flush=True)
            with logfile.open('w', encoding='utf-8') as log:
                if smoke:
                    subprocess.run(command + ['--stop-after-steps', '2'], env=env, stdout=log,
                                   stderr=subprocess.STDOUT, check=True, timeout=remaining * 60)
                    stopped = json.loads((folder / 'result.json').read_bytes())
                    if stopped['status'] != 'step_stopped' or stopped['step'] != 2:
                        raise RuntimeError('GPU interruption/recovery smoke did not stop at step two')
                subprocess.run(command + (['--resume'] if smoke else []), env=env, stdout=log,
                               stderr=subprocess.STDOUT, check=True, timeout=max(1, deadline-time.monotonic()))
            result = json.loads((folder / 'result.json').read_bytes())
            if result['status'] != 'complete' or result['completed_epochs'] != protocol['epochs']:
                raise RuntimeError(f"Incomplete fit: {job['run']}")
            if result['identity']['device_type'] != 'cuda':
                raise RuntimeError('Fit did not use CUDA')
            record = {**job, 'gpu_slot': gpu, 'result_sha256': digest(folder / 'result.json'),
                      'bundle_sha256': digest(folder / 'bundle/bundle.json'),
                      'best': result['best'], 'parameters': result['parameters'],
                      'elapsed_seconds': result['elapsed_seconds']}
            print(json.dumps({'event': 'fit_complete', 'run': job['run'],
                              'tune_recall': result['best']['metrics']['recall']}), flush=True)
            return record
        finally:
            slots.put(gpu)

    candidates = []
    for model, rates in protocol['learning_rates'].items():
        for number, lr in enumerate(rates):
            config_id = f'{model}-lr{number}'
            candidates.append({'id': model, 'model': model, 'view': 'all', 'seed': 17,
                               'lr': lr, 'config_id': config_id, 'run': f'candidates/{config_id}',
                               'data_variant': 'primary'})
    first = fit(candidates[0], smoke=True)
    with ThreadPoolExecutor(max_workers=slots.qsize()) as pool:
        records = [first, *list(pool.map(fit, candidates[1:]))]
    selected = []
    for model in protocol['learning_rates']:
        alternatives = [r for r in records if r['model'] == model]
        selected.append(min(alternatives, key=lambda r: candidate_rank(r['best'], r['parameters'], r['config_id'])))
    frozen = {'schema': 'xran-campaign-selection-v1', 'selection_frozen_at': datetime.now(timezone.utc).isoformat(),
              'protocol_sha256': digest(protocol_path), 'primary': selected, 'candidates': records,
              'selection_inputs': 'seed17 tune outcomes only; no calibration/test outcomes'}
    atomic_json(out / 'selection.json', frozen)
    remaining_jobs = []
    for choice in selected:
        for seed in protocol['stability_seeds']:
            remaining_jobs.append({k: choice[k] for k in ('id', 'model', 'view', 'lr', 'config_id', 'data_variant')} |
                                  {'seed': seed, 'run': f"stability/{choice['model']}-seed{seed}"})
    count_choice = next(r for r in selected if r['model'] == 'counts')
    for identity, view, variant in [('counts_api', 'api', 'primary'),
                                    ('counts_missingness', 'missingness', 'primary'),
                                    ('counts_api_component', 'api', 'api-component')]:
        remaining_jobs.append({'id': identity, 'model': 'counts', 'view': view, 'lr': count_choice['lr'],
                               'config_id': identity, 'data_variant': variant, 'seed': 17,
                               'run': 'diagnostics/' + identity})
    with ThreadPoolExecutor(max_workers=slots.qsize()) as pool:
        extra = list(pool.map(fit, remaining_jobs))
    summary = {'schema': 'xran-campaign-complete-v1', 'primary': selected,
               'stability': [r for r in extra if r['run'].startswith('stability/')],
               'diagnostics': [r for r in extra if r['run'].startswith('diagnostics/')],
               'protocol_sha256': digest(out / 'protocol.json'), 'selection_sha256': digest(out / 'selection.json'),
               'selection_frozen_at': frozen['selection_frozen_at'], 'cuda_used': True,
               'gpu_restart_smoke_passed': True, 'test_outcomes_opened': False,
               'elapsed_seconds': time.monotonic() - started,
               'files': {p.relative_to(out).as_posix(): digest(p) for p in sorted(out.rglob('*'))
                         if p.is_file() and p.name != 'campaign-state.json'}}
    atomic_json(out / 'campaign-complete.json', summary)
    atomic_json(out / 'campaign-state.json', {**initial, 'status': 'complete',
                                            'elapsed_seconds': summary['elapsed_seconds']})
    print(json.dumps({'event': 'campaign_complete', 'elapsed_seconds': summary['elapsed_seconds']}), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-dir', required=True)
    parser.add_argument('--protocol', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--budget-minutes', type=float, default=90)
    parser.add_argument('--reserve-minutes', type=float, default=30)
    parser.add_argument('--elapsed-before-seconds', type=float, default=0)
    run(parser.parse_args())
