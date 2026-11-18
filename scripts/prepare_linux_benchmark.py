"""Prepare pinned CRIBA recordings and scoped benign captures for Linux evaluation."""

import argparse
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
import hashlib
import heapq
import json
import math
from pathlib import Path, PurePosixPath
import shutil
import tarfile
from urllib.request import urlopen
import zipfile


REVISION = 'b5e006ae9628e3a5361697adb9e6bb3086862660'
REPOSITORY = 'https://github.com/dsrhaslab/criba'
RAW = f'https://raw.githubusercontent.com/dsrhaslab/criba/{REVISION}/traces'
HORIZON = 2048
TRACE_KEYS = ('trace_id', 'label', 'role', 'group_id', 'apis')
SOURCES = {
    'avos': ('AvosLocker', 'train', 'runs.tar.gz', 3, 'b0b47487d5569277d8c81184b95252e9499961f563cb1847f1a826dd4deab866'),
    'darkside': ('DarkSide', 'test', 'runs.tar.gz', 3, 'a9e0cf1a7b9d00bbe23037c50e12a9fa5a86ed7ef8b1c57c1058e45b36c0349f'),
    'erebus': ('Erebus', 'test', 'runs.zip', 2, 'b77d8fe4b58aa07efa6a7cafa59fc37bca3a169115d9791497ee1a55c96b1e02'),
    'ransomexx': ('RansomEXX', 'train', 'runs.tar.gz', 3, 'd4202bcf4af8a52c80c727bb8d292596fde2d0dafae2023c9830673d85e25249'),
    'revil': ('REvil', 'train', 'runs.tar.gz', 3, '6bb742f27115e6a095eaa33ac8ed25dfcf2d7b0558a2b310420edcc29fbf149c'),
}
OPERATION_NAMES = {
    'open': ('open', 'openat', 'openat2', 'creat'),
    'read': ('read', 'pread64', 'readv', 'preadv', 'preadv2'),
    'write': ('write', 'pwrite64', 'writev', 'pwritev', 'pwritev2'),
    'close': ('close',),
    'rename': ('rename', 'renameat', 'renameat2'),
    'unlink': ('unlink', 'unlinkat'),
    'truncate': ('truncate', 'ftruncate'),
}
CALLS = {name: operation for operation, names in OPERATION_NAMES.items() for name in names}


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def archive_path(root, family, download):
    _, _, filename, _, expected = SOURCES[family]
    path = root / family / filename
    if not path.is_file() and download:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + '.part')
        try:
            with urlopen(f'{RAW}/{family}/{filename}', timeout=45) as source, temporary.open('wb') as stream:
                shutil.copyfileobj(source, stream, length=1024 * 1024)
            if sha256(temporary) != expected:
                raise ValueError(f'Publisher archive hash mismatch for {family}')
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
    if not path.is_file():
        raise FileNotFoundError(f'Missing source {path}. Fetch the published data with --download.')
    if sha256(path) != expected:
        raise ValueError(f'Publisher archive hash mismatch for {family}')
    return path


def read_prefix(stream):
    earliest = []
    total = 0
    for row, line in enumerate(stream):
        if b'"system_call_name"' not in line:
            continue
        event = json.loads(line)
        operation = CALLS.get(event['system_call_name'])
        if operation is None or event['return_value'] < 0:
            continue
        completed = event['return_timestamp']
        if type(completed) is not int or completed <= 0 or completed < event['call_timestamp']:
            raise ValueError(f'Invalid completion timestamp on record {row + 1}')
        total += 1
        # The archive can interleave threads. Keep the earliest completed calls
        # over the whole capture and use source order to break timestamp ties.
        entry = (-completed, -row, operation)
        if len(earliest) < HORIZON:
            heapq.heappush(earliest, entry)
        elif entry > earliest[0]:
            heapq.heapreplace(earliest, entry)
    if not earliest:
        raise ValueError('CRIBA capture has no eligible completed operations')
    ordered = sorted((-completion, -row, operation) for completion, row, operation in earliest)
    origin = ordered[0][0]
    return [operation for _, _, operation in ordered], [(time - origin) / 1e6 for time, _, _ in ordered], total


def read_family(root, family, download):
    display_name, role, _, captures, archive_digest = SOURCES[family]
    path = archive_path(root, family, download)
    result = []

    def read_capture(name, stream):
        run = PurePosixPath(name).parent.name
        if run not in {f'run{index}' for index in range(1, captures + 1)}:
            raise ValueError(f'Unexpected capture name {name}')
        tokens, elapsed, total = read_prefix(stream)
        capture = f'criba/{family}/{run}'
        result.append({'trace_id': f'criba-{family}-{run}', 'label': 'RANSOMWARE', 'role': role,
                       'group_id': f'criba-family-{family}', 'apis': tokens, 'elapsed_ms': elapsed,
                       'capture': capture, 'family': display_name, 'source': 'CRIBA SysTracer',
                       'eligible_events': total, 'source_member': name, 'archive_sha256': archive_digest})

    if path.suffix == '.zip':
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                if member.filename.endswith('/dio-trace.json') and not member.is_dir():
                    with archive.open(member) as stream:
                        read_capture(member.filename, stream)
    else:
        with tarfile.open(path, 'r|gz') as archive:
            for member in archive:
                if member.name.endswith('/dio-trace.json') and member.isfile():
                    with archive.extractfile(member) as stream:
                        read_capture(member.name, stream)
    if len({row['capture'] for row in result}) != captures or len(result) != captures:
        raise ValueError(f'Unexpected number of unique {display_name} captures')
    return sorted(result, key=lambda row: row['trace_id'])


def write_lines(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.part')
    with temporary.open('w', encoding='utf-8', newline='\n') as stream:
        for row in rows:
            stream.write(json.dumps(row, separators=(',', ':'), allow_nan=False) + '\n')
    temporary.replace(path)


def read_lines(path):
    with path.open(encoding='utf-8') as stream:
        return [json.loads(line) for line in stream if line.strip()]


def validate_row(row, label):
    required = set(TRACE_KEYS) | {'capture', 'source', 'family' if label == 'RANSOMWARE' else 'workload'}
    if not required.issubset(row) or row['label'] != label:
        raise ValueError('Invalid capture metadata')
    if row['role'] not in ('train', 'calibrate', 'test') or (label == 'RANSOMWARE' and row['role'] == 'calibrate'):
        raise ValueError(f"Unexpected statistical role for {row['trace_id']}")
    for key in required - {'apis', 'label'}:
        if not isinstance(row[key], str) or not row[key].strip():
            raise ValueError(f'Invalid {key}')
    elapsed = row.get('elapsed_ms', row.get('times_ms'))
    operations = row['apis']
    if (not isinstance(operations, list) or not 0 < len(operations) <= HORIZON
            or any(operation not in OPERATION_NAMES for operation in operations)
            or not isinstance(elapsed, list) or len(elapsed) != len(operations)
            or any(type(time) not in (float, int) or not math.isfinite(time) for time in elapsed)
            or elapsed[0] != 0 or any(left > right for left, right in zip(elapsed, elapsed[1:]))):
        raise ValueError(f"Invalid operations or elapsed time for {row['trace_id']}")
    return elapsed


def merge(positive_path, benign_path, output, audit_path):
    rows = []
    traces = {}
    captures = set()
    groups = {}
    earliest_role = {}
    duplicates = []
    role_priority = {'test': 0, 'calibrate': 1, 'train': 2}
    positive = read_lines(positive_path)
    benign = read_lines(benign_path)
    expected_positive = {
        f'criba-{family}-run{index}': (display, role, f'criba-family-{family}', f'criba/{family}/run{index}', digest)
        for family, (display, role, _, count, digest) in SOURCES.items()
        for index in range(1, count + 1)
    }
    if {row.get('trace_id') for row in positive} != expected_positive.keys():
        raise ValueError('The CRIBA input must include every pinned capture')
    for source, label in ((positive, 'RANSOMWARE'), (benign, 'BENIGN')):
        for row in source:
            elapsed = validate_row(row, label)
            if label == 'RANSOMWARE':
                provenance = tuple(row.get(key) for key in ('family', 'role', 'group_id', 'capture', 'archive_sha256'))
                if provenance != expected_positive[row['trace_id']]:
                    raise ValueError(f"CRIBA capture provenance differs from the fixed split for {row['trace_id']}")
            if row['trace_id'] in traces or row['capture'] in captures:
                raise ValueError(f"Duplicate capture or trace ID {row['trace_id']}")
            if groups.setdefault(row['group_id'], row['role']) != row['role']:
                raise ValueError(f"Group spans roles {row['group_id']}")
            captures.add(row['capture'])
            traces[row['trace_id']] = {key: value for key, value in row.items() if key not in TRACE_KEYS and key != 'times_ms'}
            traces[row['trace_id']]['elapsed_ms'] = elapsed
            rows.append({key: row[key] for key in TRACE_KEYS})

    retained = []
    for row in sorted(rows, key=lambda row: (role_priority[row['role']], row['trace_id'])):
        sequence = tuple(row['apis'])
        if earliest_role.setdefault(sequence, row['role']) != row['role']:
            duplicates.append(row['trace_id'])
            del traces[row['trace_id']]
        else:
            retained.append(row)
    support = Counter(f"{row['role']}/{row['label']}" for row in retained)
    for role, label in (('train', 'RANSOMWARE'), ('train', 'BENIGN'), ('calibrate', 'BENIGN'),
                        ('test', 'RANSOMWARE'), ('test', 'BENIGN')):
        if not support[f'{role}/{label}']:
            raise ValueError(f'No captures for {role}/{label}')
    held_out = {traces[row['trace_id']]['family'] for row in retained if row['label'] == 'RANSOMWARE' and row['role'] == 'test'}
    if held_out != {'DarkSide', 'Erebus'}:
        raise ValueError('The benchmark requires both prespecified held-out ransomware families')
    positive_test_prefixes = [row['apis'] for row in retained if row['label'] == 'RANSOMWARE' and row['role'] == 'test']

    write_lines(output, sorted(retained, key=lambda row: row['trace_id']))
    audit = {
        'title': 'Held-out Linux capture benchmark', 'schema': 'linux-benchmark-cohort-v1',
        'training_jsonl_sha256': sha256(output), 'role_counts': dict(sorted(support.items())),
        'max_observations': HORIZON, 'operation_mapping': OPERATION_NAMES,
        'distinct_test_positive_prefixes': {str(position): len({tuple(apis[:position]) for apis in positive_test_prefixes})
                                            for position in (120, HORIZON)},
        'cross_role_duplicate_exclusions': duplicates, 'trace_provenance': traces,
        'criba_revision': REVISION, 'criba_positive_jsonl_sha256': sha256(positive_path),
        'benign_jsonl_sha256': sha256(benign_path),
        'provenance': [
            {'name': 'CRIBA SysTracer', 'url': f'{REPOSITORY}/tree/{REVISION}/traces',
             'detail': 'Recorded Linux syscall completions. BSD-3-Clause source repository. AvosLocker, RansomEXX and REvil train; DarkSide and Erebus held out.'},
            {'name': 'Busy benign Docker captures', 'detail': 'Scoped local workloads traced with strace under the same successful-operation projection.'},
        ],
        'limitations': [
            'Collectors and execution environments differ by class despite a shared operation vocabulary. Performance can reflect measurement or host differences.',
            'Repeated CRIBA captures from a family come from the same published experiment. Two held-out families limit generalization.',
            'Benign workload repetitions share a local Docker environment. Capture false-alarm rates do not estimate production host-day rates.',
            'Elapsed time starts at the first retained completed operation. A retained prefix does not establish execution start, first file damage, or files saved.',
        ],
    }
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = audit_path.with_suffix(audit_path.suffix + '.part')
    temporary.write_text(json.dumps(audit, indent=2, allow_nan=False) + '\n', encoding='utf-8')
    temporary.replace(audit_path)
    return support


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    extract = commands.add_parser('extract', help='Project archived CRIBA recordings into successful operations')
    extract.add_argument('--raw', type=Path, default=Path('data/raw/criba'))
    extract.add_argument('--download', action='store_true', help='Download the pinned author data archives')
    extract.add_argument('--output', type=Path, required=True)
    extract.add_argument('--workers', type=int, default=len(SOURCES))
    combine = commands.add_parser('merge', help='Combine provenance-checked recordings and save the cohort audit')
    combine.add_argument('--positive', type=Path, required=True)
    combine.add_argument('--benign', type=Path, required=True)
    combine.add_argument('--output', type=Path, required=True)
    combine.add_argument('--audit', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'extract':
        if args.workers < 1:
            parser.error('--workers must be positive')
        with ProcessPoolExecutor(max_workers=min(args.workers, len(SOURCES))) as workers:
            tasks = [workers.submit(read_family, args.raw, family, args.download) for family in SOURCES]
            rows = [row for task in tasks for row in task.result()]
        write_lines(args.output, rows)
        print(json.dumps(dict(Counter(row['family'] for row in rows)), sort_keys=True))
    else:
        if len({path.resolve() for path in (args.positive, args.benign, args.output, args.audit)}) != 4:
            parser.error('Input, output and audit paths must be distinct')
        counts = merge(args.positive, args.benign, args.output, args.audit)
        print(json.dumps(dict(counts), sort_keys=True))


if __name__ == '__main__':
    main()
