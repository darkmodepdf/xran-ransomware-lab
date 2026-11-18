"""Stage private, hash-bound Kaggle inputs for the XRan endpoint campaign."""

import argparse
import ast
from datetime import datetime, timezone
import hashlib
import inspect
import json
from pathlib import Path
import re
import shutil
import tarfile


ROOT = Path(__file__).resolve().parents[1]
COMMIT = '2cfebbfe45d3ed47b0204096186877e5991d6324'
DATA_FILES = ('encoded.npz', 'groups.jsonl', 'vocabulary.json', 'manifest.json')
CODE_FILES = ('src/raneval/__init__.py', 'src/raneval/train_xran.py', 'src/raneval/xran_models.py',
              'src/raneval/xran_metrics.py', 'scripts/run_xran_campaign.py')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def stage_prepared_data(input_root, data_dir, hashes, sizes, archive_sha):
    """Verify the attached dataset before copying it to a writable directory."""
    matches = sorted(p.parent for p in input_root.rglob('protocol.json')
                     if p.parent.name == 'xran-prepared' and p.is_file())
    archives = sorted(p for p in input_root.rglob('xran-prepared.tar.gz') if p.is_file())
    if len(matches) + len(archives) != 1:
        raise ValueError(f'Expected one XRan input, found {len(matches)} unpacked folders and {len(archives)} archives')
    if matches:
        source = matches[0]
        for name, expected_hash in hashes.items():
            file = source / name
            if not file.is_file() or file.stat().st_size != sizes[name] or digest(file) != expected_hash:
                raise ValueError(f'Unpacked XRan input does not match its frozen hash: {name}')
        for name in hashes:
            target = data_dir / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / name, target)
        return 'kaggle_unpacked_directory'
    if digest(archives[0]) != archive_sha:
        raise ValueError('XRan archive hash mismatch')
    with tarfile.open(archives[0], 'r:gz') as archive:
        members = archive.getmembers()
        if len(members) != len(hashes) or {m.name for m in members} != set(hashes):
            raise ValueError('Unexpected data package membership')
        for member in members:
            if not member.isfile() or member.size != sizes[member.name]:
                raise ValueError(f'Unexpected data member: {member.name}')
            target = data_dir / member.name
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as stream, target.open('xb') as output:
                shutil.copyfileobj(stream, output)
            if digest(target) != hashes[member.name]:
                raise ValueError(f'Data hash mismatch: {member.name}')
    return 'archive'


DRIVER = '''
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import time
import zlib

started = time.monotonic()
import numpy as np
import torch

working = Path('/kaggle/working')
stage = Path('/tmp/xran-campaign-input')
stage.mkdir(exist_ok=False)
for name, packed in CODE.items():
    content = zlib.decompress(base64.b64decode(packed))
    if hashlib.sha256(content).hexdigest() != CODE_HASHES[name]:
        raise ValueError(f'Code hash mismatch: {name}')
    path = stage / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()
''' + '\n' + inspect.getsource(stage_prepared_data) + '''

data_dir = stage / 'prepared'
data_dir.mkdir()
input_layout = stage_prepared_data(Path('/kaggle/input'), data_dir, DATA_HASHES, DATA_SIZES, DATA_ARCHIVE_SHA)

environment = {'python': platform.python_version(), 'torch': str(torch.__version__), 'numpy': np.__version__,
               'cuda': torch.version.cuda, 'cpu_count': os.cpu_count(),
               'ram': Path('/proc/meminfo').read_text().splitlines()[:3],
               'free_working_bytes': shutil.disk_usage(working).free,
               'internet_requested': False, 'budget_minutes': BUDGET, 'reserve_minutes': RESERVE,
               'gpus': [{'name': torch.cuda.get_device_properties(i).name,
                         'vram_bytes': torch.cuda.get_device_properties(i).total_memory}
                        for i in range(torch.cuda.device_count())],
               'input_sha256': DATA_ARCHIVE_SHA, 'input_layout': input_layout,
               'verified_input_files': len(DATA_HASHES), 'code_sha256': CODE_HASHES}
(working / 'xran-environment.json').write_text(json.dumps(environment, indent=2))
print(json.dumps(environment), flush=True)
if not environment['gpus'] or environment['free_working_bytes'] < 1024 ** 3:
    raise RuntimeError('Kaggle GPU or working space preflight failed')
subprocess.run([sys.executable, str(stage / 'scripts/run_xran_campaign.py'),
                '--data-dir', str(data_dir), '--protocol', str(data_dir / 'protocol.json'),
                '--out', str(working / 'xran-campaign'), '--budget-minutes', str(BUDGET),
                '--reserve-minutes', str(RESERVE), '--elapsed-before-seconds', str(time.monotonic()-started)],
               env=dict(os.environ, PYTHONPATH=str(stage / 'src'), CUBLAS_WORKSPACE_CONFIG=':4096:8'),
               check=True, timeout=BUDGET * 60 - (time.monotonic()-started))
'''


def write_kernel_program(path, constants):
    program = '\n'.join(f'{key} = {value!r}' for key, value in constants.items()) + '\n' + DRIVER
    compile(program, 'run_xran.py', 'exec')
    path.write_text(program, encoding='utf-8')


def retry_package(previous, out):
    """Reuse the verified data attachment, protocol and training code from a failed run."""
    previous, out = previous.resolve(), out.resolve()
    original = json.loads((previous / 'package-manifest.json').read_bytes())
    if original.get('schema') != 'xran-kaggle-package-v1' or original.get('private') is not True:
        raise ValueError('Expected a private XRan package')
    for name in ('kernel/run_xran.py', 'kernel/kernel-metadata.json'):
        if digest(previous / name) != original['files'][name]:
            raise ValueError(f'Original notebook package changed: {name}')
    if digest(previous / 'protocol.json') != original['protocol_sha256']:
        raise ValueError('Original protocol changed')
    names = {'CODE', 'CODE_HASHES', 'DATA_HASHES', 'DATA_SIZES', 'DATA_ARCHIVE_SHA', 'BUDGET', 'RESERVE'}
    constants = {}
    for statement in ast.parse((previous / 'kernel/run_xran.py').read_text(encoding='utf-8')).body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            break
        target = statement.targets[0]
        if not isinstance(target, ast.Name) or target.id not in names:
            break
        constants[target.id] = ast.literal_eval(statement.value)
    if constants.keys() != names or constants['DATA_HASHES'] != original['data_sha256']:
        raise ValueError('Original notebook does not bind the prepared dataset')
    remote = json.loads((previous / 'kernel/kernel-metadata.json').read_bytes())
    if remote['dataset_sources'] != [original['dataset_ref']] or remote['is_private'] is not True:
        raise ValueError('Original notebook data attachment or privacy setting changed')
    owner = original['kernel_ref'].split('/')[0]
    tag = datetime.now(timezone.utc).strftime('%m%d-%H%M%S')
    remote['id'] = f'{owner}/raneval-xran-models-retry-{tag}'
    remote['title'] = 'RanEval XRan models retry ' + tag
    kernel = out / 'kernel'
    out.mkdir(parents=True, exist_ok=False)
    kernel.mkdir()
    shutil.copyfile(previous / 'protocol.json', out / 'protocol.json')
    write_kernel_program(kernel / 'run_xran.py', constants)
    write_json(kernel / 'kernel-metadata.json', remote)
    manifest = {**original, 'retry_of': original['kernel_ref'], 'kernel_ref': remote['id'],
                'files': {p.relative_to(out).as_posix(): digest(p) for p in sorted(kernel.iterdir())}}
    write_json(out / 'package-manifest.json', manifest)
    print(json.dumps({'dataset': manifest['dataset_ref'], 'kernel': manifest['kernel_ref'],
                      'retry_of': manifest['retry_of'], 'folder': str(out)}, indent=2))


def package(args):
    import base64
    import zlib

    data, out = args.data_dir.resolve(), args.out.resolve()
    if not re.fullmatch('[A-Za-z0-9_-]+', args.owner):
        raise ValueError('Kaggle account slug is invalid')
    source = {}
    manifests = {}
    for variant, prefix in [('primary', ''), ('api-component', 'api-component/')]:
        manifest = json.loads((data / prefix / 'manifest.json').read_bytes())
        if manifest['inputs']['commit'] != COMMIT or manifest['group_count'] != 22445:
            raise ValueError('Prepared input does not identify the pinned XRan feature cohort')
        manifests[variant] = manifest['identity_sha256']
        for name in DATA_FILES:
            path = data / prefix / name
            if name != 'manifest.json' and digest(path) != manifest['artifacts'][name]['sha256']:
                raise ValueError(f'Prepared artifact hash mismatch: {path}')
            source[prefix + name] = path
    reproducibility = json.loads((data / 'reproducibility.json').read_bytes())
    if not reproducibility['all_artifacts_byte_identical']:
        raise ValueError('Preparation reproducibility check is incomplete')
    for name, path in source.items():
        if digest(path) != reproducibility['artifact_sha256'][name]:
            raise ValueError(f'Artifact differs from the reproducibility receipt: {name}')
    dataset_dir, kernel_dir = out / 'dataset', out / 'kernel'
    out.mkdir(parents=True, exist_ok=False)
    dataset_dir.mkdir()
    kernel_dir.mkdir()
    protocol = {'schema': 'xran-campaign-protocol-v1', 'source_commit': COMMIT,
                'datasets': manifests, 'primary_seed': 17, 'stability_seeds': [29, 43],
                'epochs': 10, 'batch_size': 128, 'weight_decay': 0.0001,
                'learning_rates': {'counts': [0.003, 0.01], 'cnn': [0.0003, 0.001], 'gru': [0.0003, 0.001]},
                'selection': 'tune recall at 5%, then ROC-AUC, parameter count, config ID',
                'final_backend': 'Windows PyTorch CPU batch 1', 'calibration_alpha': 0.05,
                'diagnostics': ['counts_api', 'counts_missingness', 'counts_api_component'],
                'heldout_sources': 'deferred', 'created_at': datetime.now(timezone.utc).isoformat()}
    write_json(out / 'protocol.json', protocol)
    source['protocol.json'] = out / 'protocol.json'
    hashes = {name: digest(path) for name, path in source.items()}
    sizes = {name: path.stat().st_size for name, path in source.items()}
    archive_path = dataset_dir / 'xran-prepared.tar.gz'
    with tarfile.open(archive_path, 'w:gz', compresslevel=5) as archive:
        for name, path in sorted(source.items()):
            archive.add(path, arcname=name, recursive=False)
    archive_sha = digest(archive_path)
    tag = datetime.now(timezone.utc).strftime('%m%d-%H%M%S')
    dataset_slug = 'raneval-xran-features-' + tag
    notebook_slug = 'raneval-xran-models-' + tag
    dataset_ref, kernel_ref = f'{args.owner}/{dataset_slug}', f'{args.owner}/{notebook_slug}'
    notice = ('XRan published feature release. Gulmez, Kakisim, and Sogukpinar (2024), '
              'Computers & Security 139, 103703. https://doi.org/10.1016/j.cose.2024.103703\n'
              f'https://github.com/sibelgulmez/XRan/tree/{COMMIT}\n'
              'Private project training input derived solely from the pinned feature CSVs.\n')
    (dataset_dir / 'ATTRIBUTION.txt').write_text(notice, encoding='utf-8')
    write_json(dataset_dir / 'dataset-metadata.json', {'id': dataset_ref,
               'title': 'RanEval XRan features ' + tag, 'licenses': [{'name': 'other'}], 'description': notice})
    code = {name: (ROOT / name).read_bytes() for name in CODE_FILES}
    code_hashes = {name: hashlib.sha256(value).hexdigest() for name, value in code.items()}
    constants = {'CODE': {name: base64.b64encode(zlib.compress(value)).decode() for name, value in code.items()},
                 'CODE_HASHES': code_hashes, 'DATA_HASHES': hashes, 'DATA_SIZES': sizes,
                 'DATA_ARCHIVE_SHA': archive_sha, 'BUDGET': 90, 'RESERVE': 30}
    write_kernel_program(kernel_dir / 'run_xran.py', constants)
    write_json(kernel_dir / 'kernel-metadata.json', {'id': kernel_ref, 'title': 'RanEval XRan models ' + tag,
               'code_file': 'run_xran.py', 'language': 'python', 'kernel_type': 'script', 'is_private': True,
               'enable_gpu': True, 'enable_internet': False, 'dataset_sources': [dataset_ref],
               'kernel_sources': [], 'competition_sources': []})
    manifest = {'schema': 'xran-kaggle-package-v1', 'dataset_ref': dataset_ref, 'kernel_ref': kernel_ref,
                'private': True, 'budget_minutes': 90, 'reserve_minutes': 30,
                'dataset_archive_sha256': archive_sha, 'protocol_sha256': digest(out / 'protocol.json'),
                'code_sha256': code_hashes, 'data_sha256': hashes, 'publisher_license': 'unspecified',
                'files': {p.relative_to(out).as_posix(): digest(p) for folder in (dataset_dir, kernel_dir)
                          for p in sorted(folder.iterdir()) if p.is_file()}}
    write_json(out / 'package-manifest.json', manifest)
    print(json.dumps({'dataset': dataset_ref, 'kernel': kernel_ref,
                      'archive_bytes': archive_path.stat().st_size, 'folder': str(out)}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-dir', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--owner')
    parser.add_argument('--retry-from', type=Path, help='Build a new notebook using an existing private dataset package')
    args = parser.parse_args()
    if args.retry_from:
        if args.data_dir or args.owner:
            parser.error('--retry-from reuses the original data and owner')
        retry_package(args.retry_from, args.out)
    else:
        if not args.data_dir or not args.owner:
            parser.error('--data-dir and --owner are required for a new package')
        package(args)
