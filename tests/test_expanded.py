import json
from pathlib import Path
import tempfile
import unittest

from raneval.expanded import choose_candidate, compare, development_copy, summarize


def alert(label, index):
    return {'trace_id': label, 'group_id': label, 'label': label, 'length': 512, 'first_observation': index}


class ExpandedProtocolTests(unittest.TestCase):
    def test_development_copy_omits_calibration_and_test(self):
        with tempfile.TemporaryDirectory() as scratch:
            source = Path(scratch) / 'all.jsonl'
            destination = Path(scratch) / 'development.jsonl'
            rows = [{'role': role, 'apis': [role]} for role in ('train', 'tune', 'calibrate', 'test')]
            source.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
            development_copy(source, destination)
            self.assertEqual([json.loads(line) for line in destination.read_text().splitlines()], rows[:2])

    def test_selection_favors_alarm_limit_and_test_gate_checks_both_negative_types(self):
        reference = [alert('RANSOMWARE', 200), alert('BENIGN', None), alert('OTHER_MALWARE', None)]
        cautious = [alert('RANSOMWARE', 100), alert('BENIGN', None), alert('OTHER_MALWARE', None)]
        excessive = [alert('RANSOMWARE', 10), alert('BENIGN', None), alert('OTHER_MALWARE', 400)]
        choice = choose_candidate({'refit': summarize(reference), 'early': summarize(cautious),
                                   'early_long': summarize(excessive)})
        self.assertEqual(choice, 'early')
        self.assertTrue(compare(cautious, reference)['empirical_target_met'])
        failed = compare(excessive, reference)
        self.assertEqual(failed['other_malware_alarms']['delta_count'], 1)
        self.assertFalse(failed['empirical_target_met'])

    def test_paired_gate_rejects_different_test_groups(self):
        reference = [alert('RANSOMWARE', 120), alert('BENIGN', None), alert('OTHER_MALWARE', None)]
        changed = [dict(row) for row in reference]
        changed[0]['group_id'] = 'different'
        with self.assertRaisesRegex(ValueError, 'provenance or horizon'):
            compare(changed, reference)


if __name__ == '__main__':
    unittest.main()
