"""Protect the publication boundary independently of local generated artifacts."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('repo_audit',ROOT/'scripts/audit_repository.py')
audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)


class PublicationGuardTests(unittest.TestCase):
    def test_secrets_are_detected_without_echoing_values(self):
        credential=('ghp_'+'A'*36).encode()
        result=audit.inspect('docs/example.md',credential)
        self.assertIn('GitHub credential',result)
        self.assertNotIn(credential.decode(),str(result))
        known=b'local-session-value-with-enough-entropy'
        self.assertIn('matches a known local session credential',audit.inspect('docs/example.md',known,[known]))

    def test_private_artifacts_and_unselected_weights_rejected(self):
        for path in ['data/raw/report.json','runs/result.json','.local/session.json','nested/.env.local','kaggle.json','benign.7z','models/unselected.pt']:
            self.assertTrue(audit.inspect(path,b'{}'),path)
        self.assertTrue(audit.inspect('safe.py',b'x',mode='120000'))
        self.assertTrue(audit.inspect('large.md',b'x'*(audit.MAX_BYTES+1)))

    def test_sources_models_and_empty_example_allowed(self):
        for path in ['src/raneval/windows_native.py','demo/windows_streaming/native-model.json','.env.example','uv.lock','models/xran-endpoint/cnn/weights.pt']:
            self.assertEqual(audit.inspect(path,b'{}'),[],path)

    @unittest.skipUnless(shutil.which('git'),'Git required for ignore-boundary check')
    def test_ignore_rules_cover_nested_secrets_and_keep_required_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)
            (target/'.gitignore').write_bytes((ROOT/'.gitignore').read_bytes())
            subprocess.run(['git','init','-q'],cwd=target,check=True,capture_output=True)
            ignored=['.env','.env.local','.local/session.json','nested/credentials.json','nested/.env.production','data/raw/report.json','runs/state.json','benign.7z','XRan.pdf','.venv/pyvenv.cfg','nested/__pycache__/x.pyc','models/unselected.pt']
            allowed=['.env.example','pyproject.toml','uv.lock','README.md','src/raneval/windows_native.py','demo/windows_streaming/native-model.json','models/xran-endpoint/cnn/weights.pt','docs/experiments/native-v2/manifest.json']
            for name in ignored+allowed:
                result=subprocess.run(['git','check-ignore','--no-index','-q',name],cwd=target)
                self.assertEqual(result.returncode,0 if name in ignored else 1,name)


if __name__=='__main__':unittest.main()
