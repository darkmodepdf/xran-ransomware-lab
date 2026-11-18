import json,unittest
from collections import defaultdict
from pathlib import Path

class FrozenEvidenceTests(unittest.TestCase):
    def test_original_capture_identities_never_cross_roles(self):
        root=Path(__file__).resolve().parents[1]
        split=json.loads((root/'demo/windows_streaming/split.json').read_text(encoding='utf8'))
        seen=defaultdict(set)
        for r in split['reports']:
            for field in ('group_id','raw_sha256','sample_sha256','sequence_sha256'):
                seen[(field,r[field])].add(r['role'])
        self.assertTrue(all(len(roles)==1 for roles in seen.values()))
        self.assertEqual({r['role'] for r in split['reports']},{'train','tune','calibrate','test'})
    def test_full_audit_denominators_and_calibration_are_measured(self):
        root=Path(__file__).resolve().parents[1]
        audit=json.loads((root/'data/processed/en2025-streaming/audit.json').read_text(encoding='utf8'))
        self.assertEqual(audit['selected'],360);self.assertEqual(len(audit['reports']),360)
        self.assertEqual(audit['dispositions'],{'projected':360})
        self.assertEqual(sum(r['counts']['calls'] for r in audit['reports']),audit['totals']['calls'])
        model=json.loads((root/'demo/windows_streaming/model.json').read_text(encoding='utf8'))['payload']
        self.assertGreater(model['threshold'],model['calibration']['maximum'])
        self.assertEqual(model['calibration']['benign_sessions'],28)
