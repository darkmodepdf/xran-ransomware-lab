"""Extract only verified regular CAPE report members from EN2025 archives."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from download_en2025 import ARCHIVES


def list_members(archive: Path, label: str) -> list[dict]:
    result = subprocess.run(['tar', '-tvf', str(archive)], check=True, capture_output=True, text=True, encoding='utf-8')
    report_name = re.compile(rf'{re.escape(label)}/[0-9a-f]{{64}}/report\.json\Z')
    inventory = []
    for line in result.stdout.splitlines():
        # bsdtar verbose output: mode links owner group size month day time-or-year path.
        fields = line.split(maxsplit=8)
        if len(fields) != 9 or not fields[4].isdecimal():
            raise ValueError(f'Unrecognized tar member listing in {archive.name}: {line!r}')
        mode, member = fields[0], fields[8]
        is_report = mode.startswith('-') and report_name.fullmatch(member) is not None
        if is_report:
            status = 'regular_report'
        elif mode.startswith('d'):
            status = 'directory'
        elif member.lower().endswith('.pcap') or member.lower().endswith('.pcapng'):
            status = 'network_capture_excluded'
        elif report_name.fullmatch(member) is not None:
            status = 'nonregular_report_excluded'
        else:
            status = 'other_member_excluded'
        inventory.append({'member': member, 'mode': mode, 'expanded_bytes': int(fields[4]), 'status': status})
    return inventory


def extract(archive: Path, output: Path, limit: int, seed: int):
    label = archive.stem
    if label not in ARCHIVES:
        raise ValueError(f'Unexpected archive name: {archive.name}')
    size, expected_md5 = ARCHIVES[label]
    with archive.open('rb') as source:
        digest = hashlib.file_digest(source, 'md5').hexdigest()
    if archive.stat().st_size != size or digest != expected_md5:
        raise ValueError(f'Archive checksum or size mismatch: {archive.name}')
    inventory = list_members(archive, label)
    reports = [entry for entry in inventory if entry['status'] == 'regular_report']
    members = [entry['member'] for entry in reports]
    if not members or len(members) != len(set(members)):
        raise ValueError('Expected unique regular report.json members')
    ranked = sorted(members, key=lambda member: hashlib.sha256(f'{seed}:{member}'.encode()).digest())
    selected = ranked[:limit] if limit else ranked
    selected_set = set(selected)
    sizes = {entry['member']: entry['expanded_bytes'] for entry in reports}
    total_size = sum(sizes[name] for name in selected)
    output.mkdir(parents=True, exist_ok=True)
    manifest_path = output / f'{label}-extraction.json'
    if (output / label).exists() or manifest_path.exists():
        raise FileExistsError(f'Select a fresh extraction root: {output / label}')
    free = shutil.disk_usage(output).free
    if free < total_size + max(total_size // 5, 16 * 1024 * 1024):
        raise OSError(f'Insufficient space for {label}: {total_size:,} bytes plus headroom, {free:,} bytes free')
    print(f'{label}: extracting {len(selected)}/{len(members)} regular reports ({total_size:,} bytes)', flush=True)
    with tempfile.TemporaryDirectory(prefix=f'.{label}-extract-', dir=output) as temporary:
        staging = Path(temporary)
        member_list = staging / 'members.txt'
        member_list.write_text('\n'.join(selected) + '\n', encoding='ascii')
        subprocess.run(['tar', '-xf', str(archive.resolve()), '-C', str(staging.resolve()), '-T', str(member_list.resolve())], check=True)
        for member in selected:
            path = staging / member
            if (not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(staging.resolve())
                    or path.stat().st_size != sizes[member]):
                raise ValueError(f'Missing or invalid extracted member: {member}')
        actual = {path.relative_to(staging).as_posix() for path in (staging / label).rglob('*') if path.is_file()}
        if actual != selected_set:
            raise ValueError('Extracted file inventory differs from selected members')
        (staging / label).rename(output / label)
    for entry in reports:
        entry['status'] = 'extracted_report' if entry['member'] in selected_set else 'excluded_by_pilot_limit'
    manifest = {
        'source': 'https://zenodo.org/records/18218588', 'archive': archive.name, 'md5': digest,
        'archive_bytes': size, 'seed': seed, 'available_regular_reports': len(members), 'selected': selected,
        'extracted_bytes': total_size, 'member_inventory': inventory,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    print(f'{label}: extracted {len(selected)}/{len(members)} verified report members', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--limit-per-class', type=int, default=0, help='Zero selects all reports.')
    parser.add_argument('--seed', type=int, default=3105)
    parser.add_argument('archive', type=Path, nargs='+')
    args = parser.parse_args()
    if args.limit_per_class < 0:
        parser.error('--limit-per-class must be nonnegative')
    for archive in args.archive:
        extract(archive, args.out, args.limit_per_class, args.seed)


if __name__ == '__main__':
    main()
