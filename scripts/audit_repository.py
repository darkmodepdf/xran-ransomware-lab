"""Fail closed before publication: inspect Git-index bytes, paths, sizes and secrets.

This is a local guard, not a substitute for a dedicated secret scanner. Never
prints matched credentials. Use --working-tree before staging, then repeat with
the default index mode immediately before committing/pushing.
"""
import argparse
from fnmatch import fnmatch
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 5 * 1024 * 1024
SELECTED_WEIGHTS = {f'models/xran-endpoint/{name}/weights.pt' for name in ('cnn', 'counts', 'gru')}
PRIVATE_ROOTS = {'data', 'runs', 'tmp', '.local', '.secrets', 'secrets', 'credentials',
                 '_bmad', '.agents', '.codex', '.git', '.venv', '.venv-raneval', 'venv', 'env'}
FORBIDDEN_SUFFIXES = {'.7z', '.zip', '.rar', '.tar', '.gz', '.tgz', '.bz2', '.xz',
                      '.csv', '.parquet', '.pcap', '.pcapng', '.exe', '.dll', '.pem',
                      '.key', '.pfx', '.p12', '.pt', '.pth', '.onnx', '.pkl', '.pickle',
                      '.npz', '.npy', '.bin', '.pdf', '.log', '.pid', '.pyc'}
PATTERNS = {
    'GitHub credential': rb'(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})',
    'AWS access identifier': rb'AKIA[0-9A-Z]{16}',
    'private key': rb'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----',
    'embedded HTTP basic credential': rb'https?://[^\s/:]+:[^\s/@]+@',
    'literal bearer credential': rb'Bearer [A-Za-z0-9_-]{32,}',
}


def inspect(path, data, local_secrets=(), mode='100644'):
    """Return descriptions only; never expose matched data."""
    p = PurePosixPath(path)
    lower = path.lower()
    findings = []
    if mode == '120000':
        findings.append('symbolic links are not accepted for this release')
    if p.parts and (p.parts[0] in PRIVATE_ROOTS or p.parts[0].startswith('.venv')):
        findings.append('private/generated directory')
    if any(part in {'__pycache__', '.pytest_cache', 'node_modules'} for part in p.parts):
        findings.append('cache/dependency directory')
    if p.name=='.memlog.md':
        findings.append('local agent memory')
    if p.name != '.env.example' and (p.name == '.env' or p.name.startswith('.env.')):
        findings.append('environment credential file')
    if any(fnmatch(p.name.lower(), pattern) for pattern in ('*credentials*.json', 'secrets.json', 'tokens.json', 'kaggle.json')):
        findings.append('credential filename')
    if p.suffix.lower() in FORBIDDEN_SUFFIXES and path not in SELECTED_WEIGHTS:
        findings.append('raw/generated/binary artifact extension')
    if len(data) > MAX_BYTES:
        findings.append(f'file exceeds {MAX_BYTES} byte release limit')
    for description, pattern in PATTERNS.items():
        if re.search(pattern, data):
            findings.append(description)
    if any(secret in data for secret in local_secrets):
        findings.append('matches a known local session credential')
    return findings


def secret_values(path):
    value = json.loads(path.read_text(encoding='utf-8-sig'))
    result = set()

    def visit(item):
        if isinstance(item, dict):
            for key, value in item.items():
                if isinstance(value, str) and len(value) >= 24 and (key.lower() in ('control', 'agent', 'password', 'secret') or 'token' in key.lower() or 'api_key' in key.lower()):
                    result.add(value.encode())
                else:
                    visit(value)
        elif isinstance(item, list):
            for value in item:
                visit(value)
    visit(value)
    return result


def git(*args):
    return subprocess.run(['git', *args], cwd=ROOT, check=True, capture_output=True).stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--working-tree', action='store_true')
    parser.add_argument('--secrets-file', action='append', type=Path, default=[])
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    local = set()
    for path in args.secrets_file:
        local.update(secret_values(path))
    if args.working_tree:
        names = sorted(set(n.decode('utf8') for n in git('ls-files', '-co', '--exclude-standard', '-z').split(b'\0') if n))
        entries = [(name, '100644', (ROOT/name).read_bytes()) for name in names if (ROOT/name).is_file()]
    else:
        entries = []
        for entry in git('ls-files', '--stage', '-z').split(b'\0'):
            if not entry:
                continue
            metadata, name = entry.split(b'\t', 1)
            mode, blob, stage = metadata.decode().split()
            if stage != '0':
                raise ValueError('Unmerged Git index; resolve before publication')
            entries.append((name.decode('utf8'), mode, git('cat-file', 'blob', blob)))
    if not entries:
        raise ValueError('No files found; stage the intended release first')
    failures = []
    digest = hashlib.sha256()
    size = 0
    for name, mode, data in entries:
        reasons = inspect(name, data, local, mode)
        if reasons:
            failures.append(dict(path=name, reasons=reasons))
        digest.update(name.encode()+b'\0'+hashlib.sha256(data).digest())
        size += len(data)
    result = dict(passed=not failures, source='working-tree' if args.working_tree else 'git-index',
                  files=len(entries), total_bytes=size, content_digest=digest.hexdigest(),
                  known_local_credentials_checked=len(local), failures=failures)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(result, indent=2), encoding='utf8')
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
