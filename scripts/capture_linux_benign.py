"""Record generated busy benign workloads inside a disposable Linux container."""

import argparse
import ast
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
import gzip
import hashlib
import json
from pathlib import Path
import platform
import posixpath
import random
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile


SYSCALLS = {
    'open': ('open', 'openat', 'openat2', 'creat'),
    'read': ('read', 'pread64', 'readv', 'preadv', 'preadv2'),
    'write': ('write', 'pwrite64', 'writev', 'pwritev', 'pwritev2'),
    'close': ('close',),
    'rename': ('rename', 'renameat', 'renameat2'),
    'unlink': ('unlink', 'unlinkat'),
    'truncate': ('truncate', 'ftruncate'),
}
EVENT = {name: operation for operation, names in SYSCALLS.items() for name in names}
LINE = re.compile(r'^(\d+)\s+(\d+(?:\.\d+)?)\s+(.*)$')
CALL = re.compile(r'^(\w+)\(')
RESUMED = re.compile(r'^<\.\.\. (\w+) resumed>')
RETURN = re.compile(r'\)\s+=\s+(-?\d+)\b.*\s+<(\d+(?:\.\d+)?)>$')
OPEN_PATH = re.compile(r'<(/[^>]+)>')
FD_PATH = re.compile(r'^-?\d+<(/[^>]+)>')
PATH_ARG = re.compile(r'^(?:(?:AT_FDCWD|-?\d+)(?:<([^>]+)>)?,\s*)?("(?:\\.|[^"\\])*")')
WORKLOADS = ('Tree backup', 'Archive compression', 'Python bytecode build', 'SQLite updates', 'Log rotation')
ROTATION_VARIANTS = ('rename-and-compress', 'copy-and-truncate', 'delayed-compression')
CAP = 2048


def syscall_records(lines, source):
    pending = {}
    for sequence, line in enumerate(lines):
        match = LINE.match(line)
        if match is None:
            continue
        pid, timestamp, call = match.groups()
        timestamp = Decimal(timestamp)
        resumed = RESUMED.match(call)
        if resumed:
            name = resumed[1]
            previous = pending.pop((pid, name), None)
            if previous is None:
                raise ValueError(f'Unmatched resumed syscall in {source}')
            start, prefix = previous
            call = prefix + call[resumed.end():]
        else:
            initial = CALL.match(call)
            if not initial:
                continue
            name, start = initial[1], timestamp
            if call.endswith('<unfinished ...>'):
                pending[(pid, name)] = start, call.removesuffix('<unfinished ...>')
                continue
        result = RETURN.search(call)
        if result and name in EVENT:
            yield start + Decimal(result[2]), sequence, pid, name, call, result
    if pending:
        raise ValueError(f'Incomplete syscalls at end of {source}')


def syscall_path(name, call, result, workspace):
    operation = EVENT[name]
    arguments = call[len(name) + 1:result.start()]
    if operation == 'open':
        match = OPEN_PATH.match(call, result.end(1))
        if match:
            path = match[1]
        else:
            return None
    elif operation in ('read', 'write', 'close') or name == 'ftruncate':
        match = FD_PATH.match(arguments)
        if match is None:
            return None
        path = match[1]
    else:
        match = PATH_ARG.match(arguments)
        if match is None:
            return None
        try:
            path = ast.literal_eval(match[2])
        except (ValueError, SyntaxError):
            return None
        if not posixpath.isabs(path):
            path = posixpath.join(match[1] or str(workspace), path)
    path = posixpath.normpath(path.removesuffix(' (deleted)'))
    if not path.startswith('/') or path.startswith(('/dev/', '/proc/', '/sys/')):
        return None
    return path


class CaptureContext:
    """Convert observed task and pathname equivalence into capture-local IDs."""

    def __init__(self, workspace):
        self.workspace = workspace
        self.actors = {}
        self.files = {}
        self.directories = {}

    def event(self, record):
        _, _, pid, name, call, result = record
        operation = EVENT[name]
        actor = self.actors.setdefault(pid, f'a{len(self.actors):x}')
        path = syscall_path(name, call, result, self.workspace)
        file_id = directory_id = None
        if path is not None:
            file_id = self.files.setdefault(path, f'f{len(self.files):x}')
            directory = posixpath.dirname(path)
            directory_id = self.directories.setdefault(directory, f'd{len(self.directories):x}')
        return {'op': operation, 'actor': actor, 'file': file_id, 'directory': directory_id,
                'bytes_changed': int(result[1]) if operation == 'write' else None}


def observed_events(records, context, max_events=0):
    """Project successful calls in emission order and retain exact completion times."""
    epoch = None
    latest = Decimal(0)
    emitted = 0
    for record in records:
        if int(record[-1][1]) < 0 or max_events and emitted >= max_events:
            continue
        if epoch is None:
            epoch = record[0]
        latest = max(latest, (record[0] - epoch) * 1000)
        emitted += 1
        yield {**context.event(record), 'schema': 'raneval-observed-syscall-v1', 'order': 'observed',
               'sequence': emitted, 'completion_time_ns': int(record[0] * 1_000_000_000),
               'time_ms': float(latest)}


def read_completed(path, context=None, order='completed'):
    with path.open(encoding='utf-8') as trace:
        records = list(syscall_records(trace, path.name))
    completed = [record for record in records if int(record[-1][1]) >= 0]
    if order == 'completed':
        completed.sort()
    elif order != 'observed' or context is None:
        raise ValueError('Observed order requires file and process context')
    if len(completed) < 120:
        raise ValueError(f'Only {len(completed)} successful operations in {path.name}')
    prefix = completed[:CAP]
    if order == 'observed':
        projected = list(observed_events(prefix, context))
        return ([event['op'] for event in projected], [event['time_ms'] for event in projected],
                len(completed), len(records), projected)
    epoch = prefix[0][0]
    return ([EVENT[record[3]] for record in prefix], [float((record[0] - epoch) * 1000) for record in prefix],
            len(completed), len(records), [context.event(record) for record in prefix] if context else None)


def make_inputs(root, rng, *, source_files):
    root.mkdir()
    for index in range(rng.randrange(150, 340)):
        directory = root / f'module-{rng.randrange(8, 27)}'
        directory.mkdir(exist_ok=True)
        if source_files:
            (directory / f'helper_{index}.py').write_text(f'VALUE = {rng.getrandbits(48)}\n', encoding='utf-8')
        else:
            size = rng.choice((192, 640, 2048, 9000, 33000, 66000))
            (directory / f'fixture-{index}.bin').write_bytes(rng.randbytes(size))


def sqlite_updates(seed):
    rng = random.Random(seed)
    with sqlite3.connect('benchmark.sqlite') as database:
        database.execute('PRAGMA journal_mode=WAL')
        database.execute('CREATE TABLE readings (key INTEGER PRIMARY KEY, payload BLOB)')
        for batch in range(rng.randrange(82, 176)):
            with database:
                database.executemany('INSERT INTO readings (key, payload) VALUES (?, ?)', (
                    (batch * 10 + index, rng.randbytes(rng.randrange(90, 1600))) for index in range(10)
                ))
            if batch % 12 == 11:
                database.execute('PRAGMA wal_checkpoint(TRUNCATE)')


def log_rotation(seed):
    rng = random.Random(seed)
    active = Path('service.log')
    for batch in range(rng.randrange(123, 262)):
        with active.open('xb') as log:
            for index in range(rng.randrange(4, 20)):
                log.write(f'{batch}:{index} INFO record {rng.getrandbits(64):016x}\n'.encode())
        rotated = active.rename(f'service-{batch}.log')
        with rotated.open('rb') as text, gzip.open(f'service-{batch}.log.gz', 'xb', compresslevel=3) as archive:
            shutil.copyfileobj(text, archive)
        rotated.unlink()


def varied_log_rotation(seed, variant):
    """Append generated records to service logs and rotate local archives."""
    rng = random.Random(seed)
    active_logs = [Path(f'service-{index}.log') for index in range(rng.randrange(2, 6))]
    pending_archives = []

    def compress(path):
        with path.open('rb') as source, gzip.open(path.with_suffix('.gz'), 'xb', compresslevel=3) as archive:
            shutil.copyfileobj(source, archive, length=rng.choice((512, 2048, 8192)))
        path.unlink()

    for batch in range(rng.randrange(90, 160)):
        active = rng.choice(active_logs)
        with active.open('ab', buffering=rng.choice((0, 128, 512, 4096))) as log:
            for index in range(rng.randrange(3, 16)):
                payload = rng.randbytes(rng.randrange(10, 96)).hex()
                log.write(f'{batch}:{index} INFO {payload}\n'.encode())
                if rng.randrange(6) == 0:
                    log.flush()
        if rng.randrange(5) == 0:
            with active.open('rb') as log:
                log.read(rng.randrange(200, 1800))
        if rng.randrange(5) == 0:
            continue
        rotated = Path(f'archive-{batch}.log')
        if variant == 'copy-and-truncate':
            with active.open('rb') as log, rotated.open('xb') as archive:
                shutil.copyfileobj(log, archive, length=rng.choice((256, 2048, 8192)))
            with active.open('r+b') as log:
                log.truncate(0)
        else:
            active.rename(rotated)
        pending_archives.append(rotated)
        if variant != 'delayed-compression' or len(pending_archives) >= rng.randrange(2, 7):
            compress(pending_archives.pop(0))
    for archive in pending_archives:
        compress(archive)


def workload_command(workload, workspace, seed, rotation_variant):
    if workload in WORKLOADS[:3]:
        make_inputs(workspace / 'input', random.Random(seed), source_files=workload == WORKLOADS[2])
    if workload == 'Tree backup':
        return ['cp', '-a', 'input', 'backup']
    if workload == 'Archive compression':
        return ['tar', '-czf', 'backup.tar.gz', 'input']
    if workload == 'Python bytecode build':
        return [sys.executable, '-B', '-m', 'compileall', '-q', 'input']
    if rotation_variant:
        return [sys.executable, '-B', '-c',
                'import sys; from capture_linux_benign import varied_log_rotation; '
                'varied_log_rotation(int(sys.argv[1]), sys.argv[2])', str(seed), rotation_variant]
    function = 'sqlite_updates' if workload == 'SQLite updates' else 'log_rotation'
    return [sys.executable, '-B', '-c',
            f'from capture_linux_benign import {function}; {function}(int(__import__("sys").argv[1]))', str(seed)]


def trace_command(output, include_context, workload):
    decode = ['-y'] if include_context else []
    return ['strace', '-f', '-ttt', '-T', '-s', '0', '-qq', *decode, '-e', 'trace=' + ','.join(EVENT),
            '-o', str(output), '--', *workload]


def trace_environment():
    return {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LC_ALL': 'C',
            'PYTHONPATH': str(Path(__file__).resolve().parent)}


def collect(category, number, role, scratch, campaign, base_seed, rotation_variant, include_context=False,
            attempt=0, order='completed'):
    workload = WORKLOADS[category]
    seed = base_seed + 1000 * category + number + 10000 * attempt
    run_id = f'benign-{category:02}-{number:02}'
    if campaign:
        run_id = f'{campaign}-{run_id}'
    else:
        seed = base_seed + 100 * category + number
    with tempfile.TemporaryDirectory(dir=scratch, prefix=f'{run_id}-') as temporary:
        workspace = Path(temporary)
        command = workload_command(workload, workspace, seed, rotation_variant)
        raw = workspace / 'syscalls.txt'
        try:
            subprocess.run(trace_command(raw, include_context, command), cwd=workspace, check=True, timeout=90,
                           env=trace_environment(), capture_output=True, text=True)
        except subprocess.CalledProcessError as error:
            raise RuntimeError(f'{workload} capture {run_id} failed: {error.stderr.strip()}') from error
        context = CaptureContext(workspace) if include_context else None
        events, times, eligible, parsed, context_events = read_completed(raw, context, order)
        with raw.open('rb') as stream:
            raw_sha256 = hashlib.file_digest(stream, 'sha256').hexdigest()
    row = {'trace_id': run_id, 'label': 'BENIGN', 'role': role, 'group_id': run_id, 'apis': events,
           'capture': run_id, 'workload': workload, 'times_ms': times, 'source': 'Local Linux strace',
           'raw_trace_sha256': raw_sha256, 'eligible_events': eligible, 'parsed_calls': parsed, 'seed': seed}
    if campaign:
        row.update(campaign=campaign, rotation_variant=rotation_variant, capture_attempt=attempt + 1)
    if context_events is not None:
        row['events'] = context_events
    if order == 'observed':
        row['order'] = order
    return row


def capture_tasks(args):
    tasks = []
    for category, workload in enumerate(WORKLOADS):
        rotation = workload == 'Log rotation'
        train, calibrate, test = args.rotation_per_role if rotation and args.rotation_per_role else args.per_role
        tune = args.rotation_tune if rotation and args.rotation_tune is not None else args.tune_per_workload
        number = 0
        for role, count in (('train', train), ('tune', tune), ('calibrate', calibrate), ('test', test)):
            for repeat in range(count):
                variant = ROTATION_VARIANTS[repeat % len(ROTATION_VARIANTS)] if rotation and args.diverse_rotation else None
                tasks.append(dict(category=category, number=number, role=role, scratch=args.scratch,
                                  campaign=args.campaign, base_seed=args.seed, rotation_variant=variant,
                                  include_context=args.context, order=args.order))
                number += 1
    return tasks


def collect_distinct(pool, tasks, excluded):
    """Fill every fixed capture slot using seeds independent of detector scores."""
    priority = {'test': 0, 'calibrate': 1, 'tune': 2, 'train': 3}
    outstanding = sorted(tasks, key=lambda task: (priority[task['role']], task['category'], task['number']))
    accepted = []
    current = set()
    rejections = Counter()
    for attempt in range(6):
        pending = []
        rows = pool.map(lambda task: collect(**task, attempt=attempt), outstanding)
        for task, row in zip(outstanding, rows):
            sequence = tuple(row['apis'])
            if sequence in excluded or sequence in current:
                rejections['prior_benchmark' if sequence in excluded else 'current_campaign'] += 1
                pending.append(task)
            else:
                accepted.append(row)
                current.add(sequence)
        if not pending:
            return sorted(accepted, key=lambda row: row['trace_id']), dict(rejections)
        outstanding = pending
    raise ValueError(f'Could not produce distinct event sequences for {len(outstanding)} fixed capture slots')


def excluded_sequences(paths):
    excluded = set()
    hashes = {}
    for path in paths:
        with path.open('rb') as stream:
            hashes[path.name] = hashlib.file_digest(stream, 'sha256').hexdigest()
            stream.seek(0)
            excluded.update(tuple(json.loads(line)['apis'][:CAP]) for line in stream if line.strip())
    return excluded, hashes


def observe(workload, scratch, seed, rotation_variant, max_events=0):
    """Emit completed kernel calls from one generated workload as strace writes them."""
    with tempfile.TemporaryDirectory(dir=scratch, prefix='observe-') as temporary:
        workspace = Path(temporary)
        command = workload_command(workload, workspace, seed, rotation_variant)
        trace = trace_command('/dev/stderr', True, command)
        context = CaptureContext(workspace)
        emitted = 0
        with subprocess.Popen(['timeout', '--kill-after=2s', '90s', *trace], cwd=workspace,
                              env=trace_environment(), stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE, text=True) as process:
            records = syscall_records(process.stderr, 'observed workload')
            for event in observed_events(records, context, max_events):
                print(json.dumps(event, separators=(',', ':')), flush=True)
                emitted += 1
        if process.returncode or emitted == 0:
            raise RuntimeError(f'{workload} observation failed (exit {process.returncode}, {emitted} events)')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--output', type=Path, help='Write a benchmark campaign to this JSONL path')
    mode.add_argument('--observe', choices=WORKLOADS, help='Stream one generated workload as contextual NDJSON')
    parser.add_argument('--scratch', type=Path, default=Path('/work'))
    parser.add_argument('--workers', type=int, choices=range(1, 5), default=2)
    parser.add_argument('--per-role', type=int, nargs=3, metavar=('TRAIN', 'CALIBRATE', 'TEST'), default=(4, 8, 8))
    parser.add_argument('--tune-per-workload', type=int, default=0)
    parser.add_argument('--rotation-per-role', type=int, nargs=3, metavar=('TRAIN', 'CALIBRATE', 'TEST'))
    parser.add_argument('--rotation-tune', type=int)
    parser.add_argument('--diverse-rotation', action='store_true')
    parser.add_argument('--rotation-variant', choices=ROTATION_VARIANTS, help='Variant for --observe "Log rotation"')
    parser.add_argument('--context', action='store_true', help='Include capture-local task and filesystem context')
    parser.add_argument('--order', choices=('completed', 'observed'),
                        help='Offline projection order; live streams always use observed order')
    parser.add_argument('--max-events', type=int, default=0,
                        help='Limit live emitted events; zero streams the complete workload')
    parser.add_argument('--campaign', help='Trace ID prefix for a new cohort with unique projected sequences')
    parser.add_argument('--seed', type=int, default=39017)
    parser.add_argument('--exclude', type=Path, action='append', default=[], help='Prior trace JSONL to check for exact matches')
    args = parser.parse_args()
    if platform.system() != 'Linux':
        parser.error('A Linux recorder is required')
    if args.rotation_variant and args.observe != 'Log rotation':
        parser.error('--rotation-variant requires --observe "Log rotation"')
    if args.max_events < 0:
        parser.error('--max-events must be nonnegative')
    if args.observe:
        if args.order == 'completed':
            parser.error('Live capture supports --order observed')
        variant = (args.rotation_variant or ROTATION_VARIANTS[0]) if args.observe == 'Log rotation' else None
        observe(args.observe, args.scratch, args.seed, variant, args.max_events)
        return
    if args.max_events:
        parser.error('--max-events applies to live observation')
    args.order = args.order or 'completed'
    if args.order == 'observed' and not args.context:
        parser.error('--order observed requires --context')
    if any(count < 1 for count in args.per_role):
        parser.error('Positive run counts are required')
    if args.rotation_per_role and any(count < 1 for count in args.rotation_per_role):
        parser.error('Positive rotation run counts are required')
    if args.tune_per_workload < 0 or (args.rotation_tune is not None and args.rotation_tune < 0):
        parser.error('Tuning run counts cannot be negative')
    if args.campaign and not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,31}', args.campaign):
        parser.error('Campaign must use up to 32 lowercase letters, digits or hyphens')
    if args.exclude and not args.campaign:
        parser.error('--exclude requires a new --campaign')
    if args.output.resolve() in {path.resolve() for path in args.exclude}:
        parser.error('Output cannot overwrite a prior cohort used for exclusions')
    tasks = capture_tasks(args)
    if args.campaign and max(task['number'] for task in tasks) >= 1000:
        parser.error('A campaign supports up to 1,000 capture slots per workload')
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        if args.campaign:
            excluded, source_hashes = excluded_sequences(args.exclude)
            traces, rejections = collect_distinct(pool, tasks, excluded)
        else:
            traces = list(pool.map(lambda task: collect(**task), tasks))
    metadata = {'schema': 'raneval-strace-captures-v1', 'python': platform.python_version(),
                'sqlite': sqlite3.sqlite_version, 'linux_kernel': platform.release(),
                'strace': subprocess.check_output(['strace', '--version'], text=True).splitlines()[0],
                'captures_by_role': dict(Counter(row['role'] for row in traces)),
                'workloads': WORKLOADS, 'operations': SYSCALLS, 'retained_cap': CAP}
    if args.campaign:
        metadata.update(campaign=args.campaign, base_seed=args.seed, exclusion_source_hashes=source_hashes,
                        discarded_candidate_sequences=rejections,
                        rotation_variants_by_role={role: dict(Counter(row['rotation_variant'] for row in traces
                                                                      if row['role'] == role and row['rotation_variant']))
                                                   for role in ('train', 'tune', 'calibrate', 'test')})
    if args.context:
        context_keys = ('actor', 'file', 'directory', 'bytes_changed')
        metadata.update(schema='raneval-strace-captures-v2',
                        observed_context_events={key: sum(event[key] is not None
                                                                  for row in traces for event in row['events'])
                                                 for key in context_keys})
    if args.order == 'observed':
        metadata.update(schema='raneval-strace-captures-v3', order='observed',
                        event_schema='raneval-observed-syscall-v1')
    args.output.write_text(''.join(json.dumps(row, separators=(',', ':'), allow_nan=False) + '\n' for row in traces),
                           encoding='utf-8')
    args.output.with_suffix('.meta.json').write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(metadata, indent=2))


if __name__ == '__main__':
    main()
