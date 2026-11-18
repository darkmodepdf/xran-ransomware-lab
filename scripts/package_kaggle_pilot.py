"""Package the current model code and a compact development cohort for private Kaggle GPU training."""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import zlib


REPO = Path(__file__).resolve().parents[1]
PROFILES = {
    'en2025': ('EN2025 pilot', 30, 3, ()),
    'linux': ('Linux eBPF pilot', 600, 30, (
        '--endpoint-policy', 'early', '--early-loss-weight', '2', '--tune-objective', 'early120',
    )),
}

DRIVER = '''
import base64
from importlib.metadata import version
from pathlib import Path
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import zlib

started = time.monotonic()
root = Path('/kaggle/working')
inputs = Path('/tmp/raneval-pilot')
for name, encoded in PAYLOAD.items():
    path = inputs / name
    path.parent.mkdir(parents=True, exist_ok=True)
    content = zlib.decompress(base64.b64decode(encoded))
    if hashlib.sha256(content).hexdigest() != CHECKSUMS[name]:
        raise ValueError(f'Payload checksum failed for {name}')
    path.write_bytes(content)

import torch

if sys.version_info < (3, 11):
    raise RuntimeError('The checked training package requires Python 3.11 or newer')

environment = {
    'python': sys.version.split()[0], 'torch': str(torch.__version__),
    'cuda_runtime': torch.version.cuda, 'platform': platform.platform(),
    'cpu_count': os.cpu_count(), 'free_working_bytes': shutil.disk_usage(root).free,
    'memory_total': Path('/proc/meminfo').read_text().splitlines()[0],
    'numpy': version('numpy'), 'budget_minutes': BUDGET_MINUTES, 'reserve_minutes': RESERVE_MINUTES,
    'gpu': [{'name': p.name, 'vram_bytes': p.total_memory}
            for p in (torch.cuda.get_device_properties(i) for i in range(torch.cuda.device_count()))],
    'purpose': PURPOSE, 'internet_requested': False,
    'input_sha256': CHECKSUMS, 'models': ARCHITECTURES,
}
print(json.dumps(environment, indent=2), flush=True)
(root / 'environment.json').write_text(json.dumps(environment, indent=2), encoding='utf-8')
if 'input-notice.txt' in PAYLOAD:
    shutil.copyfile(inputs / 'input-notice.txt', root / 'input-notice.txt')
if not environment['gpu']:
    raise RuntimeError('GPU is required for this pilot')
if environment['free_working_bytes'] < 512 * 1024 * 1024:
    raise RuntimeError('Insufficient disk for pilot checkpoints and export')
probe = torch.ones((16, 16), device='cuda')
if (probe @ probe)[0, 0].item() != 16:
    raise RuntimeError('GPU matmul preflight failed')
del probe
env = dict(os.environ, PYTHONPATH=str(inputs / 'src'), CUBLAS_WORKSPACE_CONFIG=':4096:8')

def train(architecture, extra=()):
    remaining = BUDGET_MINUTES - 3 - (time.monotonic() - started) / 60
    if remaining <= RESERVE_MINUTES:
        raise RuntimeError('Insufficient session budget for pilot training')
    cmd = [sys.executable, '-m', 'raneval.train', '--data', str(inputs / 'traces.jsonl'),
           '--run-dir', str(root / architecture), '--architecture', architecture,
           '--device', 'cuda', '--epochs', str(EPOCHS), '--block-size', '256',
           '--horizon', '2048', '--seed', '123', '--batch-size', '32',
           '--checkpoint-seconds', '600', '--cpu-threads', '2',
           '--budget-minutes', str(remaining), '--reserve-minutes', str(RESERVE_MINUTES),
           *TRAIN_OPTIONS, *extra]
    subprocess.run(cmd, env=env, check=True, timeout=max(1, int(remaining * 60)))

artifact_hashes = {}
for architecture in ARCHITECTURES:
    if architecture == ARCHITECTURES[0]:
        train(architecture, ('--stop-after-steps', '2'))
        interrupted = root / architecture
        if (interrupted / 'metrics.json').exists():
            raise RuntimeError('Interruption smoke should leave a resumable incomplete run')
        progress = json.loads((interrupted / 'recovery.json').read_text(encoding='utf-8'))
        if progress['step'] != 2:
            raise RuntimeError('Interruption smoke did not save at optimizer step 2')
        train(architecture, ('--resume',))
    else:
        train(architecture)
    directory = root / architecture
    recovery = json.loads((directory / 'recovery.json').read_text(encoding='utf-8'))
    names = ('bundle.pt', 'frozen.json', 'metrics.json', 'test_alerts.jsonl', 'recovery.json')
    names = (*names, *(path.name for path in sorted(directory.glob('recovery-*.pt'))))
    artifact_hashes[architecture] = {}
    for name in names:
        with (directory / name).open('rb') as stream:
            artifact_hashes[architecture][name] = hashlib.file_digest(stream, 'sha256').hexdigest()
    frozen = json.loads((directory / 'frozen.json').read_text(encoding='utf-8'))
    if artifact_hashes[architecture]['bundle.pt'] != frozen['bundle_sha256']:
        raise RuntimeError(f'Bundle checksum failed for {architecture}')
    checkpoint_name = f"recovery-{recovery['slot']}.pt"
    if artifact_hashes[architecture][checkpoint_name] != recovery['sha256']:
        raise RuntimeError(f'Recovery checksum failed for {architecture}')
    state = torch.load(directory / checkpoint_name, map_location='cpu', weights_only=True)
    if state['epoch'] != EPOCHS or state['step'] != recovery['step']:
        raise RuntimeError(f'Incomplete optimizer checkpoint for {architecture}')

(root / 'pilot-complete.json').write_text(json.dumps({
    'architecture': ARCHITECTURES, 'cuda_used': True,
    'restart_smoke_passed': True, 'elapsed_seconds': time.monotonic() - started,
    'artifact_sha256': artifact_hashes,
}, indent=2), encoding='utf-8')
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--profile', choices=PROFILES, default='en2025')
    parser.add_argument('--budget-minutes', type=int, help='Override the profile session budget')
    parser.add_argument('--notice', type=Path, help='Attribution or license for the packaged cohort')
    parser.add_argument('--epochs', type=int, choices=range(1, 6), default=3)
    parser.add_argument('--models', choices=('cnn', 'gru'), nargs='+', default=['cnn', 'gru'])
    parser.add_argument('--push', action='store_true')
    args = parser.parse_args()
    if len(args.models) != len(set(args.models)):
        parser.error('--models must be unique')
    purpose, default_budget, reserve, train_options = PROFILES[args.profile]
    budget = args.budget_minutes if args.budget_minutes is not None else default_budget
    if not reserve + 3 < budget <= 720:
        parser.error(f'--budget-minutes must be greater than {reserve + 3} and at most 720')
    if args.profile == 'linux' and args.notice is None:
        parser.error('--notice is required for the Linux cohort attribution')
    from kaggle import api

    owner = api.config_values[api.CONFIG_NAME_USER]
    if not re.fullmatch(r'[A-Za-z0-9_-]+', owner):
        raise ValueError('Kaggle account slug is invalid')
    tag = datetime.now(timezone.utc).strftime('%m%d%H%M%S')
    slug = f'raneval-{args.profile}-pilot-{tag}'
    reference = f'{owner}/{slug}'
    files = {'traces.jsonl': args.data.read_bytes()}
    if args.notice is not None:
        files['input-notice.txt'] = args.notice.read_bytes()
    for source in sorted((REPO / 'src' / 'raneval').glob('*.py')):
        if not source.name.startswith('test_'):
            files[source.relative_to(REPO).as_posix()] = source.read_bytes()
    required = {'src/raneval/__init__.py', 'src/raneval/core.py', 'src/raneval/train.py', 'src/raneval/score.py'}
    if not required.issubset(files):
        raise ValueError('Training package is incomplete')
    payload = {name: base64.b64encode(zlib.compress(data, 9)).decode('ascii') for name, data in files.items()}
    if sum(map(len, payload.values())) > 2_500_000:
        raise ValueError('Pilot payload is too large to embed, use a private attached dataset for the full cohort')
    checksums = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    program = '\n'.join((f'PAYLOAD = {payload!r}', f'CHECKSUMS = {checksums!r}',
                         f'ARCHITECTURES = {args.models!r}', f'EPOCHS = {args.epochs}',
                         f'PURPOSE = {purpose!r}', f'BUDGET_MINUTES = {budget}',
                         f'RESERVE_MINUTES = {reserve}', f'TRAIN_OPTIONS = {train_options!r}', DRIVER))
    compile(program, 'run_pilot.py', 'exec')
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / 'run_pilot.py').write_text(program, encoding='utf-8')
    title_profile = 'EN2025' if args.profile == 'en2025' else 'Linux'
    metadata = {'id': reference, 'title': f'RanEval {title_profile} pilot {tag}', 'code_file': 'run_pilot.py',
                'language': 'python', 'kernel_type': 'script', 'is_private': True,
                'enable_gpu': True, 'enable_internet': False, 'dataset_sources': [],
                'kernel_sources': [], 'competition_sources': []}
    (args.out / 'kernel-metadata.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    print(f'Packaged private Kaggle job: {reference}', flush=True)
    if args.push:
        subprocess.run(['kaggle', 'kernels', 'push', '--path', str(args.out), '--accelerator', 'NvidiaTeslaT4',
                        '--timeout', str(budget * 60)], check=True)


if __name__ == '__main__':
    main()
