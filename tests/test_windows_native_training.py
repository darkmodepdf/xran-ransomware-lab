import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('train_native',ROOT/'scripts/train_windows_native.py')
training=importlib.util.module_from_spec(spec);spec.loader.exec_module(training)

class PartitionPolicyTests(unittest.TestCase):
    def test_v2_roles_seeds_profiles_and_policies_are_predeclared(self):
        declaration=training.manifest('v2');rows=declaration['campaigns']
        self.assertEqual(len(rows),230);self.assertEqual(declaration,training.manifest('v2'))
        self.assertEqual(len(set(r['id'] for r in rows)),230)
        self.assertEqual(len(set(r['campaign']['seed'] for r in rows)),230)
        for row in rows:
            if row['role']=='calibrate':self.assertEqual(row['kind'],'benign')
            if row['campaign']['profile']=='structured':self.assertEqual(row['role'],'test')
        self.assertEqual({r['campaign']['variant'] for r in rows if r['role']=='train'}, {'append','save','rotate','copy','truncate','overwrite','sparse'})
        self.assertEqual(declaration['calibration_budget'],0);self.assertEqual(declaration['trees_per_candidate'],32)
        self.assertEqual(len(declaration['model_candidates']),10)
        self.assertIn('Never adjust after opening test',declaration['cutoff_policy'])
    def test_original_manifest_remains_separate(self):
        old=training.manifest('v1');new=training.manifest('v2')
        self.assertEqual(old['version'],1);self.assertEqual(len(old['campaigns']),132)
        self.assertFalse(set(r['campaign']['seed'] for r in old['campaigns'])&set(r['campaign']['seed'] for r in new['campaigns']))

if __name__=='__main__':unittest.main()
