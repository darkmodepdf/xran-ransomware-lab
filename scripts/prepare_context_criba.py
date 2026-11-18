"""Attach causal file and process context to the pinned CRIBA operation prefixes."""

import argparse
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
import heapq
import json
from pathlib import Path
import posixpath
import tarfile
import zipfile

from prepare_linux_benchmark import CALLS, HORIZON, SOURCES, archive_path, read_lines, write_lines


def filesystem_path(value):
    if not isinstance(value, str) or not value.startswith('/'):
        return None
    path = posixpath.normpath(value)
    if path == '/dev' or path.startswith('/dev/'):
        return None
    return path


def read_prefix(stream, actor_field='pid', identity_audit=None):
    if actor_field not in {'pid', 'tid'}:
        raise ValueError('Expected pid or tid actor scope')
    paths = {}
    earliest = []
    total = 0
    for row, line in enumerate(stream):
        if b'"system_call_name"' not in line:
            if b'"EventPath"' in line:
                metadata = json.loads(line)
                if metadata.get('doc_type') == 'EventPath':
                    tag = metadata['file_tag']
                    path = filesystem_path(metadata['file_path'])
                    if paths.setdefault(tag, path) != path:
                        raise ValueError(f'Conflicting CRIBA path metadata on record {row + 1}')
            continue

        event = json.loads(line)
        operation = CALLS.get(event['system_call_name'])
        if operation is None or event['return_value'] < 0:
            continue
        completed = event['return_timestamp']
        if type(completed) is not int or completed <= 0 or completed < event['call_timestamp']:
            raise ValueError(f'Invalid completion timestamp on record {row + 1}')
        total += 1

        if len(earliest) == HORIZON and (-completed, -row) <= earliest[0][:2]:
            continue

        # EventPath metadata is emitted at the first observed access to a tagged
        # inode. Only consult metadata on preceding source records. The timestamp
        # in the tag also bounds its availability in the completion-ordered replay.
        path = filesystem_path(event.get('fdata', {}).get('file_path'))
        tag = event.get('file_tag')
        if path is None and tag in paths and int(tag.rsplit('|', 1)[-1]) <= completed:
            path = paths[tag]

        entry = (-completed, -row, operation, event.get('pid'), event.get('tid'), path, event['return_value'])
        if len(earliest) < HORIZON:
            heapq.heappush(earliest, entry)
        else:
            heapq.heapreplace(earliest, entry)

    if not earliest:
        raise ValueError('CRIBA capture has no eligible completed operations')
    entries = sorted(earliest, reverse=True)
    origin = -entries[0][0]
    elapsed = [(-completion - origin) / 1e6 for completion, *_ in entries]
    actors, files, directories = {}, {}, {}
    events = []
    processes, tasks = set(), set()
    for _, _, operation, pid, tid, path, result in entries:
        if type(pid) is int and pid > 0:
            processes.add(pid)
        if type(tid) is int and tid > 0:
            tasks.add(tid)
        actor = pid if actor_field == 'pid' else tid
        events.append({
            'op': operation,
            'actor': actors.setdefault(actor, str(len(actors))) if type(actor) is int and actor > 0 else None,
            'file': files.setdefault(path, str(len(files))) if path else None,
            'directory': directories.setdefault(posixpath.dirname(path), str(len(directories))) if path else None,
            'bytes_changed': result if operation == 'write' else None,
        })
    if identity_audit is not None:
        identity_audit.update(actor_field=actor_field, unique_processes=len(processes), unique_tasks=len(tasks),
                              missing_actor_events=sum(event['actor'] is None for event in events))
    return events, elapsed, total


def context_capture(stream, reference, actor_field='pid'):
    identity_audit = {}
    events, elapsed, total = read_prefix(stream, actor_field, identity_audit)
    ops = [event['op'] for event in events]
    if (ops, elapsed, total) != (reference['apis'], reference['elapsed_ms'], reference['eligible_events']):
        raise ValueError(f"Projected operations differ from the prior benchmark for {reference['trace_id']}")
    coverage = Counter(retained_events=len(events))
    for event in events:
        for field in ('actor', 'file', 'directory', 'bytes_changed'):
            if event[field] is not None:
                coverage[field] += 1
    return {**reference, 'events': events, 'context_coverage': dict(coverage), 'actor_identity': identity_audit}


def read_family(root, family, download, references, actor_field='pid'):
    path = archive_path(root, family, download)
    expected = {row['source_member']: row for row in references}
    rows = []
    if path.suffix == '.zip':
        with zipfile.ZipFile(path) as archive:
            for name, reference in expected.items():
                with archive.open(name) as stream:
                    rows.append(context_capture(stream, reference, actor_field))
    else:
        with tarfile.open(path, 'r|gz') as archive:
            for member in archive:
                if member.isfile() and member.name in expected:
                    with archive.extractfile(member) as stream:
                        rows.append(context_capture(stream, expected[member.name], actor_field))

    if sorted(row['trace_id'] for row in rows) != sorted(row['trace_id'] for row in references):
        raise ValueError(f'Expected every pinned capture for {family}')
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw', type=Path, default=Path('data/raw/criba'))
    parser.add_argument('--download', action='store_true', help='Fetch only the pinned recordings')
    parser.add_argument('--reference', type=Path, default=Path('data/processed/linux-benchmark-criba.jsonl'))
    parser.add_argument('--output', type=Path, default=Path('data/processed/linux-gru-context-criba.jsonl'))
    parser.add_argument('--workers', type=int, default=len(SOURCES))
    parser.add_argument('--actor-field', choices=('pid', 'tid'), default='pid',
                        help='DIO pid denotes process group; tid denotes individual task')
    args = parser.parse_args()
    if args.workers < 1 or args.reference.resolve() == args.output.resolve():
        parser.error('Use a positive worker count and distinct input and output paths')

    references = read_lines(args.reference)
    cohorts = {}
    for family, (_, role, _, count, digest) in SOURCES.items():
        rows = [row for row in references if row['group_id'] == f'criba-family-{family}']
        if (len(rows) != count or any(row['role'] != role or row['archive_sha256'] != digest for row in rows)
                or {row['trace_id'] for row in rows} != {f'criba-{family}-run{i}' for i in range(1, count + 1)}):
            raise ValueError(f'Invalid benchmark provenance for {family}')
        cohorts[family] = rows
    if sum(len(rows) for rows in cohorts.values()) != len(references):
        raise ValueError('Unexpected extra positive captures in the benchmark reference')

    with ProcessPoolExecutor(max_workers=min(args.workers, len(SOURCES))) as workers:
        tasks = [workers.submit(read_family, args.raw, family, args.download, rows, args.actor_field)
                 for family, rows in cohorts.items()]
        rows = sorted((row for task in tasks for row in task.result()), key=lambda row: row['trace_id'])
    write_lines(args.output, rows)
    coverage = {'train': Counter(), 'test': Counter()}
    for row in rows:
        coverage[row['role']].update(row['context_coverage'])
    print(json.dumps(coverage, sort_keys=True))


if __name__ == '__main__':
    main()
