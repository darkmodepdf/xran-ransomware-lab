"""Stage a private derived-data dataset and an offline Kaggle expanded-evaluation job.

Without --push this only writes a reviewable local package. Repeating the same
command validates and reuses it. No raw CAPE reports or arbitrary directories are
uploaded. Kaggle metadata references:
https://github.com/Kaggle/kaggle-cli/blob/main/docs/datasets_metadata.md
https://github.com/Kaggle/kaggle-cli/blob/main/docs/kernels_metadata.md
"""

import argparse
import base64
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import zlib


REPO = Path(__file__).resolve().parents[1]
MAX_BUDGET_MINUTES = 90
MIN_BUDGET_MINUTES = 40
SOURCE = "https://zenodo.org/records/18218588"
ATTRIBUTION = (
    "Private research staging of derived EN2025 API-name sequences and the user's "
    "previous model bundles. EN2025 creator: Ziqian Chen; source: " + SOURCE + ". "
    "The source declares the MIT license. Kaggle's 'other' category preserves this "
    "source declaration; it does not relicense source data or grant a new license "
    "to the model bundles. No original reports, API arguments, or executable "
    "binaries are included."
)

DRIVER = r'''
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import zlib

started = time.monotonic()
working = Path('/kaggle/working')
scratch = Path('/tmp/raneval-expanded-' + PACKAGE_ID)
scratch.mkdir(parents=True, exist_ok=False)

def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

preferred = Path('/kaggle/input') / DATASET_SLUG
if (preferred / DATA_FILE).is_file():
    mount = preferred
else:
    matches = list(Path('/kaggle/input').rglob(DATA_FILE))
    if len(matches) != 1 or not matches[0].is_file():
        raise RuntimeError('Expected exactly one approved data file in Kaggle inputs')
    mount = matches[0].parent
for name, expected in DATA_FILES.items():
    path = mount / name
    if not path.is_file() or digest(path) != expected:
        raise RuntimeError('Missing or mismatched approved input: ' + name)

for name, encoded in CODE.items():
    path = scratch / name
    path.parent.mkdir(parents=True, exist_ok=True)
    content = zlib.decompress(base64.b64decode(encoded))
    if hashlib.sha256(content).hexdigest() != CODE_HASHES[name]:
        raise RuntimeError('Code checksum mismatch: ' + name)
    path.write_bytes(content)

import torch
if sys.version_info < (3, 11):
    raise RuntimeError('Python 3.11+ is required')
environment = {
    'python': sys.version.split()[0], 'torch': str(torch.__version__),
    'cuda_runtime': torch.version.cuda, 'platform': platform.platform(),
    'cpu_count': os.cpu_count(), 'free_working_bytes': shutil.disk_usage(working).free,
    'free_scratch_bytes': shutil.disk_usage(scratch).free,
    'gpu': [{'name': p.name, 'vram_bytes': p.total_memory}
            for p in (torch.cuda.get_device_properties(i) for i in range(torch.cuda.device_count()))],
    'package_id': PACKAGE_ID, 'dataset_ref': DATASET_REF,
    'input_sha256': DATA_FILES, 'code_sha256': CODE_HASHES,
    'derived_jsonl_sha256': DATA_SHA256, 'derived_jsonl_bytes': DATA_BYTES,
    'budget_minutes': BUDGET_MINUTES, 'internet_requested': False,
    'purpose': 'EN2025 expanded development comparison, not locked benchmark',
}
try:
    import psutil
    environment['ram_bytes'] = psutil.virtual_memory().total
    environment['ram_available_bytes'] = psutil.virtual_memory().available
except ImportError:
    environment['ram_bytes'] = None
print(json.dumps(environment, indent=2), flush=True)
(working / 'environment.json').write_text(json.dumps(environment, indent=2), encoding='utf-8')
(working / 'package-manifest.json').write_text(json.dumps(PACKAGE_MANIFEST, indent=2), encoding='utf-8')
if not environment['gpu']:
    raise RuntimeError('This GPU job requires an accelerator')
if environment['free_scratch_bytes'] < DATA_BYTES + 1024**3 or environment['free_working_bytes'] < 2 * 1024**3:
    raise RuntimeError('Insufficient scratch/output disk headroom')

data = scratch / 'traces.jsonl'
h = hashlib.sha256()
size = 0
with gzip.open(mount / DATA_FILE, 'rb') as source, data.open('wb') as target:
    for chunk in iter(lambda: source.read(1024 * 1024), b''):
        size += len(chunk)
        if size > DATA_BYTES:
            raise RuntimeError('Approved gzip exceeds declared uncompressed size')
        h.update(chunk)
        target.write(chunk)
if size != DATA_BYTES or h.hexdigest() != DATA_SHA256:
    raise RuntimeError('Uncompressed derived data checksum mismatch')
old_root = scratch / 'old-runs'
for architecture, names in OLD_FILES.items():
    folder = old_root / architecture
    folder.mkdir(parents=True)
    for original_name, staged_name in names.items():
        shutil.copyfile(mount / staged_name, folder / original_name)

remaining = BUDGET_MINUTES - (time.monotonic() - started) / 60 - 2
if remaining <= 33:
    raise RuntimeError('Too little session budget after setup; refusing training')
env = dict(os.environ, PYTHONPATH=str(scratch / 'src'), CUBLAS_WORKSPACE_CONFIG=':4096:8')
command = [sys.executable, '-m', 'raneval.expanded', '--data', str(data),
           '--old-runs', str(old_root), '--out', str(working / 'expanded'),
           '--runtime', 'auto', '--budget-minutes', str(remaining)]
try:
    result = subprocess.run(command, env=env, timeout=max(1, int(remaining * 60)))
except subprocess.TimeoutExpired:
    (working / 'driver-result.json').write_text(json.dumps({
        'status': 'driver_timeout', 'complete': False,
        'elapsed_seconds': time.monotonic() - started, 'package_id': PACKAGE_ID,
    }, indent=2), encoding='utf-8')
    raise
expanded = working / 'expanded'
complete = result.returncode == 0 and all((expanded / name).is_file() for name in
    ('protocol.json', 'selection.json', 'comparison.json', 'paired-test-alerts.jsonl'))
budget_stopped = (expanded / 'incomplete.json').is_file() and not complete
(working / 'driver-result.json').write_text(json.dumps({
    'status': 'complete' if complete else 'budget_stopped' if budget_stopped else 'failed',
    'complete': complete, 'recoverable_budget_stop': budget_stopped,
    'exit_code': result.returncode, 'elapsed_seconds': time.monotonic() - started,
    'package_id': PACKAGE_ID,
    'note': 'A budget stop preserves partial/checkpoint outputs and is not a completed comparison.',
}, indent=2), encoding='utf-8')
if result.returncode:
    raise SystemExit(result.returncode)
'''


def sha256(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8')


def atomic_json(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_bytes(json_bytes(value))
    temporary.replace(path)


def inspect_data(path):
    counts = Counter()
    seen = set()
    groups = {}
    with path.open('r', encoding='utf-8') as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict) or set(row) != {'apis', 'trace_id', 'group_id', 'label', 'role'}:
                raise ValueError(f'Only the five approved derived-data fields are allowed (line {number})')
            if any(not isinstance(row[k], str) or not row[k] for k in ('trace_id', 'group_id', 'label', 'role')):
                raise ValueError(f'Invalid identifier on line {number}')
            if row['label'] not in {'BENIGN', 'RANSOMWARE', 'OTHER_MALWARE'} or row['role'] not in {'train', 'tune', 'calibrate', 'test'}:
                raise ValueError(f'Invalid class/role on line {number}')
            if row['role'] == 'calibrate' and row['label'] != 'BENIGN':
                raise ValueError('Calibration must contain benign traces only')
            if not isinstance(row['apis'], list) or any(not isinstance(v, str) or not v.strip() for v in row['apis']):
                raise ValueError(f'Invalid API list on line {number}')
            if row['trace_id'] in seen or groups.setdefault(row['group_id'], row['role']) != row['role']:
                raise ValueError(f'Duplicate trace or cross-role group on line {number}')
            seen.add(row['trace_id'])
            counts[f"{row['label']}/{row['role']}"] += 1
    if not seen:
        raise ValueError('No derived traces found')
    return {'trace_count': len(seen), 'class_role_counts': dict(sorted(counts.items())),
            'sha256': sha256(path), 'bytes': path.stat().st_size}


def package(data, old_runs, out, budget, owner):
    if not MIN_BUDGET_MINUTES <= budget <= MAX_BUDGET_MINUTES:
        raise ValueError('Budget must be between 40 and 90 minutes (controller reserves 30 minutes)')
    if not re.fullmatch(r'[A-Za-z0-9_-]+', owner):
        raise ValueError('Invalid Kaggle owner slug')
    data_info = inspect_data(data)
    old = {}
    for architecture in ('cnn', 'gru'):
        bundle, frozen = old_runs / architecture / 'bundle.pt', old_runs / architecture / 'frozen.json'
        if not bundle.is_file() or not frozen.is_file():
            raise ValueError(f'Missing approved old artifacts for {architecture}')
        frozen_content = json.loads(frozen.read_text(encoding='utf-8'))
        bundle_hash = sha256(bundle)
        if frozen_content.get('bundle_sha256') != bundle_hash:
            raise ValueError(f'Old {architecture} bundle does not match frozen manifest')
        old[architecture] = {'bundle.pt': bundle_hash, 'frozen.json': sha256(frozen)}
    code = {}
    for path in sorted((REPO / 'src' / 'raneval').rglob('*.py')):
        if not path.name.startswith('test_') and '__pycache__' not in path.parts:
            code[path.relative_to(REPO).as_posix()] = path.read_bytes()
    required = {'src/raneval/__init__.py', 'src/raneval/core.py', 'src/raneval/train.py', 'src/raneval/expanded.py'}
    if not required.issubset(code):
        raise ValueError('Expanded code package is incomplete: ' + ', '.join(sorted(required - code.keys())))
    code_hashes = {name: hashlib.sha256(value).hexdigest() for name, value in code.items()}
    identity = {'data': data_info, 'old': old, 'owner': owner, 'code': code_hashes,
                'budget_minutes': budget, 'packager_sha256': sha256(Path(__file__))}
    package_id = hashlib.sha256(json_bytes(identity)).hexdigest()[:16]
    dataset_id = hashlib.sha256(json_bytes({'data': data_info, 'old': old, 'attribution': ATTRIBUTION})).hexdigest()[:16]
    dataset_slug = 'raneval-expanded-data-' + dataset_id
    kernel_slug = 'raneval-expanded-' + package_id
    data_file = 'traces-' + data_info['sha256'][:16] + '.jsonl.gz'
    old_files = {arch: {name: 'old-' + arch + '-' + digest[:16] + '-' + name for name, digest in values.items()}
                 for arch, values in old.items()}
    if out.exists():
        manifest_path = out / 'package-manifest.json'
        if not manifest_path.is_file() or json.loads(manifest_path.read_text(encoding='utf-8')).get('identity') != identity:
            raise ValueError('Output exists with a different/incomplete package; use a fresh --out directory')
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        validate_package(out, manifest)
        return manifest
    out.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=out.name + '-stage-', dir=out.parent))
    dataset_dir, kernel_dir = stage / 'dataset', stage / 'kernel'
    dataset_dir.mkdir()
    kernel_dir.mkdir()
    with data.open('rb') as source, (dataset_dir / data_file).open('wb') as target:
        with gzip.GzipFile(filename='', mode='wb', fileobj=target, mtime=0, compresslevel=6) as compressed:
            shutil.copyfileobj(source, compressed, 1024 * 1024)
    for architecture, names in old_files.items():
        for original_name, staged_name in names.items():
            shutil.copyfile(old_runs / architecture / original_name, dataset_dir / staged_name)
            if sha256(dataset_dir / staged_name) != old[architecture][original_name]:
                raise ValueError('Old artifact changed during packaging')
    if sha256(data) != data_info['sha256']:
        raise ValueError('Derived data changed during packaging')
    (dataset_dir / 'ATTRIBUTION.txt').write_text(ATTRIBUTION + '\n', encoding='utf-8')
    atomic_json(dataset_dir / 'input-manifest.json', {'data': data_info, 'old': old, 'source': SOURCE})
    dataset_files = {p.name: sha256(p) for p in sorted(dataset_dir.iterdir())}
    metadata = {'id': owner + '/' + dataset_slug, 'title': 'RanEval expanded data ' + dataset_id,
                'licenses': [{'name': 'other'}], 'description': ATTRIBUTION}
    atomic_json(dataset_dir / 'dataset-metadata.json', metadata)
    manifest = {'package_id': package_id, 'dataset_ref': metadata['id'],
                'kernel_ref': owner + '/' + kernel_slug, 'identity': identity,
                'dataset_files': dataset_files, 'budget_minutes': budget,
                'private': True, 'internet_enabled': False, 'accelerator': 'NvidiaTeslaT4'}
    payload = {name: base64.b64encode(zlib.compress(value, 9)).decode('ascii') for name, value in code.items()}
    if sum(map(len, payload.values())) > 2_500_000:
        raise ValueError('Code alone exceeds the embedding cap')
    constants = {'CODE': payload, 'CODE_HASHES': code_hashes, 'PACKAGE_ID': package_id,
                 'DATASET_SLUG': dataset_slug, 'DATASET_REF': metadata['id'], 'DATA_FILE': data_file,
                 'DATA_FILES': dataset_files, 'DATA_BYTES': data_info['bytes'], 'DATA_SHA256': data_info['sha256'],
                 'OLD_FILES': old_files, 'BUDGET_MINUTES': budget, 'PACKAGE_MANIFEST': manifest}
    program = '\n'.join(f'{key} = {value!r}' for key, value in constants.items()) + '\n' + DRIVER
    compile(program, 'run_expanded.py', 'exec')
    (kernel_dir / 'run_expanded.py').write_text(program, encoding='utf-8')
    atomic_json(kernel_dir / 'kernel-metadata.json', {
        'id': manifest['kernel_ref'], 'title': 'RanEval expanded ' + package_id,
        'code_file': 'run_expanded.py', 'language': 'python', 'kernel_type': 'script',
        'is_private': True, 'enable_gpu': True, 'enable_internet': False,
        'machine_shape': 'NvidiaTeslaT4', 'dataset_sources': [metadata['id']],
        'kernel_sources': [], 'competition_sources': [], 'model_sources': [],
    })
    manifest['package_files'] = {p.relative_to(stage).as_posix(): sha256(p)
                                 for folder in (dataset_dir, kernel_dir) for p in sorted(folder.iterdir())}
    atomic_json(stage / 'package-manifest.json', manifest)
    validate_package(stage, manifest)
    stage.rename(out)
    return manifest


def validate_package(out, manifest):
    expected = manifest['package_files']
    actual = {p.relative_to(out).as_posix() for folder in ('dataset', 'kernel') for p in (out / folder).rglob('*') if p.is_file()}
    if actual != set(expected):
        raise ValueError('Unexpected or missing files in upload directories')
    for name, digest in expected.items():
        path = out / name
        if path.is_symlink() or sha256(path) != digest:
            raise ValueError('Packaged artifact changed: ' + name)


def push(out, manifest, api):
    """Resume a staged private upload without generating new remote references."""
    from kaggle.api.kaggle_api_extended import ApiGetDatasetRequest
    from requests.exceptions import HTTPError

    validate_package(out, manifest)
    state_path = out / 'submission-state.json'
    state = json.loads(state_path.read_text(encoding='utf-8')) if state_path.exists() else {}
    if state.get('kernel_submitted'):
        print('Kernel already submitted: ' + manifest['kernel_ref'], flush=True)
        return
    request = ApiGetDatasetRequest()
    request.owner_slug, request.dataset_slug = manifest['dataset_ref'].split('/')
    try:
        with api.build_kaggle_client() as client:
            remote = client.datasets.dataset_api_client.get_dataset(request)
    except HTTPError as exc:
        if exc.response is None or exc.response.status_code != 404:
            raise
        remote = None
    if remote is None:
        response = api.dataset_create_new(str(out / 'dataset'), public=False, convert_to_csv=False)
        if response.error:
            raise RuntimeError('Private dataset creation failed: ' + str(response.error))
        state['dataset_created'] = True
        atomic_json(state_path, state)
    # Processing is asynchronous. A pending dataset is a resumable condition.
    status = api.dataset_status(manifest['dataset_ref'])
    if status.lower() != 'ready':
        print(f'Dataset status is {status}; rerun the same --push command when ready.', flush=True)
        return
    with api.build_kaggle_client() as client:
        remote = client.datasets.dataset_api_client.get_dataset(request)
    if remote.is_private is not True:
        raise RuntimeError('Refusing to use a dataset that is not private')
    state['dataset_ready'] = True
    atomic_json(state_path, state)
    # Persist intent before push: after an ambiguous network failure, inspect the
    # existing kernel rather than submitting a duplicate compute job automatically.
    if state.get('kernel_push_started'):
        raise RuntimeError('Previous kernel push outcome is uncertain. Inspect Kaggle status and resolve submission-state.json before retrying.')
    state['kernel_push_started'] = True
    atomic_json(state_path, state)
    subprocess.run(['kaggle', 'kernels', 'push', '--path', str(out / 'kernel'),
                    '--accelerator', 'NvidiaTeslaT4', '--timeout', str(manifest['budget_minutes'] * 60)], check=True)
    state['kernel_submitted'] = True
    atomic_json(state_path, state)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', required=True, type=Path)
    parser.add_argument('--old-runs', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--budget-minutes', type=int, default=60)
    parser.add_argument('--push', action='store_true', help='Explicitly upload private dataset and submit when ready')
    args = parser.parse_args()
    from kaggle import api

    owner = api.config_values[api.CONFIG_NAME_USER]
    manifest = package(args.data.resolve(), args.old_runs.resolve(), args.out.resolve(), args.budget_minutes, owner)
    print(json.dumps({'package': str(args.out.resolve()), 'dataset': manifest['dataset_ref'],
                      'kernel': manifest['kernel_ref'], 'trace_count': manifest['identity']['data']['trace_count'],
                      'budget_minutes': manifest['budget_minutes'], 'private': True,
                      'uploaded': False}, indent=2), flush=True)
    if args.push:
        push(args.out.resolve(), manifest, api)


if __name__ == '__main__':
    main()
