"""Confirm inventory, cohort digest and exact prior-pilot isolation before upload."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re


EXPECTED = {'BENIGN': 919, 'RANSOMWARE': 733, 'RAT': 816, 'SPYWARE': 792}
FIELDS = ('sample_sha256', 'raw_sha256', 'full_sequence_sha256', 'retained_sequence_sha256')


def verify(data, audit_file, prior_file):
    prior_bytes = prior_file.read_bytes()
    prior = json.loads(prior_bytes)
    audit = json.loads(audit_file.read_bytes())
    assert not audit['errors']
    assert audit['development_audit_sha256'] == hashlib.sha256(prior_bytes).hexdigest()
    assert audit['max_observations'] == 2048 == prior['max_observations']
    reports = audit['reports']
    assert Counter(row['source_collection'] for row in reports) == EXPECTED
    assert len({row['source_report'] for row in reports}) == sum(EXPECTED.values())
    assert Counter(row['status'] for row in reports) == audit['statuses']
    identities = {field: {row.get(field) for row in prior['reports'] if row.get(field)} for field in FIELDS}
    for row in prior['reports']:
        match = re.search(r'/([a-fA-F0-9]{64})/report\.json$', row['source_report'])
        if match:
            identities['sample_sha256'].add(match[1].lower())
    protected_groups = {row['candidate_group_id'] for row in reports if row.get('candidate_group_id')
                        and any(row.get(field) in values for field, values in identities.items())}
    included = {row['trace_id']: row for row in reports if row['status'] == 'included'}
    assert len(included) == audit['statuses']['included']
    assert protected_groups
    digest = hashlib.sha256()
    seen = set()
    role_groups = {}
    counts = Counter()
    with data.open('rb') as source:
        for line in source:
            digest.update(line)
            row = json.loads(line)
            ident, group, role = (row[key] for key in ('trace_id', 'group_id', 'role'))
            record = included[ident]
            assert ident not in seen and role_groups.setdefault(group, role) == role
            assert (record['group_id'], record['role'], record['source_label']) == (group, role, row['label'])
            assert 0 < len(row['apis']) <= 2048 and len(row['apis']) == record['retained_observations']
            if record.get('development_group_forced_train') or group in protected_groups:
                assert role == 'train', f'Prior pilot group leaked to {role}'
            seen.add(ident)
            counts[(row['label'], role)] += 1
    assert seen == included.keys()
    assert digest.hexdigest() == audit['training_jsonl_sha256']
    for label in ('BENIGN', 'RANSOMWARE', 'OTHER_MALWARE'):
        for role in ('train', 'tune', 'test'):
            assert counts[label, role] > 0
    assert counts['BENIGN', 'calibrate'] > 0
    assert not counts['RANSOMWARE', 'calibrate'] and not counts['OTHER_MALWARE', 'calibrate']
    print(json.dumps({'included': len(seen), 'statuses': audit['statuses'], 'source_counts': EXPECTED,
                      'protected_groups': len(protected_groups), 'roles': audit['assignment_counts'],
                      'sha256': digest.hexdigest()}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', type=Path, required=True)
    parser.add_argument('--audit', type=Path, required=True)
    parser.add_argument('--prior', type=Path, required=True)
    args = parser.parse_args()
    verify(args.data, args.audit, args.prior)


if __name__ == '__main__':
    main()
