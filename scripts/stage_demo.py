"""Stage a reproducibly chosen development trace and hash-verified model for Docker."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


def stage(data, model, label, output):
    with data.open(encoding='utf-8') as source:
        eligible = []
        for line in source:
            if line.strip():
                row = json.loads(line)
                if row['role'] == 'tune' and row['label'] == label and len(row['apis']) >= 2:
                    eligible.append(row)
    if not eligible:
        raise ValueError(f'No nonempty development tuning traces for {label}')
    selected = min(eligible, key=lambda row: (hashlib.sha256(f"demo-v1:{row['trace_id']}".encode()).digest(), row['trace_id']))
    manifest = json.loads((model / 'frozen.json').read_text(encoding='utf-8'))
    with (model / 'bundle.pt').open('rb') as bundle:
        digest = hashlib.file_digest(bundle, 'sha256').hexdigest()
    if digest != manifest['bundle_sha256']:
        raise ValueError('Frozen model checksum mismatch')
    with data.open('rb') as source:
        input_digest = hashlib.file_digest(source, 'sha256').hexdigest()
    if input_digest != manifest['identity']['data_sha256']:
        raise ValueError('The model manifest refers to a different training corpus')
    horizon = manifest['identity']['config']['horizon'] or 120
    apis = selected['apis'][:min(120, horizon)]
    output.mkdir(parents=True, exist_ok=False)
    for name in ('bundle.pt', 'frozen.json'):
        shutil.copyfile(model / name, output / name)
    (output / 'apis.jsonl').write_text(''.join(json.dumps(api) + '\n' for api in apis), encoding='utf-8')
    receipt = {'trace_id': selected['trace_id'], 'label': label, 'role': 'tune',
               'selection': 'Minimum SHA-256 of demo-v1 plus trace ID, chosen without scores',
               'observations': len(apis), 'bundle_sha256': digest, 'data_sha256': input_digest}
    (output / 'selection.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    subprocess.run([sys.executable, '-m', 'raneval.score', '--bundle', str(output / 'bundle.pt'),
                    '--expected-sha256', digest, '--apis', str(output / 'apis.jsonl'), '--output', str(output / 'scores.jsonl'),
                    '--device', 'cpu', '--alpha', '0.05'], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', type=Path, required=True)
    parser.add_argument('--model', type=Path, required=True, help='Completed trainer run directory')
    parser.add_argument('--label', required=True, choices=('BENIGN', 'RANSOMWARE'))
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    stage(args.data, args.model, args.label, args.out)


if __name__ == '__main__':
    main()
