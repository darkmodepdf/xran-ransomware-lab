"""Completion-worker checks with a fake CLI; no network, training, or submission."""

import importlib.util
import json
import runpy
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("finish_xran", ROOT / "scripts/finish_xran_kaggle.py")
worker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(worker)
synthetic_report = runpy.run_path(str(ROOT / "tests/test_xran_dashboard.py"))["synthetic_report"]


class StatusParserTest(unittest.TestCase):
    def test_current_cli_enum_and_older_plain_status(self):
        for name in ("QUEUED", "RUNNING", "COMPLETE", "ERROR", "CANCEL_REQUESTED", "CANCEL_ACKNOWLEDGED", "NEW_SCRIPT"):
            self.assertEqual(worker.parse_status(f'owner/slug has status "KernelWorkerStatus.{name}"\n', "owner/slug"), name.lower())
        self.assertEqual(worker.parse_status('owner/slug has status "complete"', "owner/slug"), "complete")

    def test_failure_message_cannot_be_mistaken_for_success(self):
        self.assertEqual(worker.parse_status('owner/slug has status "error"\nFailure message: "complete failed"', "owner/slug"), "error")
        for output in ('other/slug has status "complete"', 'owner/slug has status "unknown"', 'download complete',
                       'owner/slug has status "running"\nowner/slug has status "complete"'):
            with self.assertRaises(ValueError):
                worker.parse_status(output, "owner/slug")


class WorkerFlowTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.data = self.base / "prepared"
        self.data.mkdir()
        (self.data / "manifest.json").write_text('{"fixture":true}', encoding="utf-8")
        self.out = self.base / "worker"
        self.commands = []
        self.kaggle_patch = patch.object(worker.shutil, "which", return_value="fake-kaggle")
        self.kaggle_patch.start()

    def tearDown(self):
        self.kaggle_patch.stop()
        self.temp.cleanup()

    def status(self):
        return json.loads((self.out / "completion-status.json").read_text())

    def fake_success(self, command, **options):
        self.commands.append(command)
        if command[1:3] == ["kernels", "status"]:
            return subprocess.CompletedProcess(command, 0, 'owner/slug has status "KernelWorkerStatus.COMPLETE"', "")
        if command[1:3] == ["kernels", "output"]:
            campaign = Path(command[command.index("-p") + 1]) / "campaign"
            campaign.mkdir(parents=True)
            (campaign / "campaign-complete.json").write_text('{"fixture":true}', encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, "Downloaded synthetic test artifacts", "")
        evaluation = Path(command[command.index("--out") + 1])
        campaign = Path(command[command.index("--campaign-dir") + 1])
        evaluation.mkdir(exist_ok=True)
        worker.atomic_json(evaluation / "evaluation.json", synthetic_report())
        worker.atomic_json(evaluation / "verification.json", {
            "schema": "xran-evaluation-verification-v1", "all_independent_rescores_exact": True,
            "identity": {"campaign_sha256": worker.digest(campaign / "campaign-complete.json"),
                         "data_manifest_sha256": worker.digest(self.data / "manifest.json")},
            "artifacts": {"evaluation.json": worker.digest(evaluation / "evaluation.json")},
        })
        return subprocess.CompletedProcess(command, 0, "Synthetic evaluator completed", "")

    def test_completed_flow_promotes_verified_report_and_resumes_without_network(self):
        current = worker.Worker("owner/slug", self.data, self.out, runner=self.fake_success)
        self.assertEqual(current.run(), 0)
        self.assertEqual(self.status()["phase"], "complete")
        self.assertEqual(json.loads((self.out / "evaluation.json").read_text()), synthetic_report())
        self.assertEqual(len(self.commands), 3)
        self.assertEqual(worker.Worker("owner/slug", self.data, self.out, runner=self.fake_success).run(), 0)
        self.assertEqual(len(self.commands), 3)
        self.assertFalse(any("push" in command for command in self.commands))

    def test_once_records_running_without_downloading(self):
        def running(command, **kwargs):
            self.commands.append(command)
            return subprocess.CompletedProcess(command, 0, 'owner/slug has status "running"', "")
        self.assertEqual(worker.Worker("owner/slug", self.data, self.out, once=True, runner=running).run(), 0)
        self.assertEqual(self.status()["kernel_status"], "running")
        self.assertFalse((self.out / "evaluation.json").exists())
        self.assertEqual(len(self.commands), 1)

    def test_terminal_failure_never_downloads_or_exposes_report(self):
        def failed(command, **kwargs):
            self.commands.append(command)
            return subprocess.CompletedProcess(command, 0, 'owner/slug has status "KernelWorkerStatus.ERROR"\nFailure message: "GPU unavailable"', "")
        self.assertEqual(worker.Worker("owner/slug", self.data, self.out, runner=failed).run(), 1)
        self.assertEqual(self.status()["phase"], "kernel_failed")
        self.assertIn("GPU unavailable", self.status()["status_message"])
        self.assertFalse((self.out / "evaluation.json").exists())
        self.assertEqual(len(self.commands), 1)

    def test_corrupt_evaluation_receipt_never_promotes(self):
        def tampered(command, **kwargs):
            result = self.fake_success(command, **kwargs)
            if "--campaign-dir" in command:
                report = self.out / "verified-evaluation/evaluation.json"
                report.write_text("{}", encoding="utf-8")
            return result
        self.assertEqual(worker.Worker("owner/slug", self.data, self.out, runner=tampered).run(), 1)
        self.assertEqual(self.status()["phase"], "failed")
        self.assertIn("checksum mismatch", self.status()["last_error"])
        self.assertFalse((self.out / "evaluation.json").exists())

    def test_campaign_selection_requires_exactly_one_marker(self):
        self.out.mkdir()
        with self.assertRaisesRegex(ValueError, "found 0"):
            worker.find_campaign(self.out)
        for name in ("one", "two"):
            path = self.out / name
            path.mkdir()
            (path / "campaign-complete.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "found 2"):
            worker.find_campaign(self.out)

    def test_exclusive_lock_releases_after_exit(self):
        self.out.mkdir()
        lock = self.out / "worker.lock"
        with worker.worker_lock(lock):
            with self.assertRaises(RuntimeError):
                with worker.worker_lock(lock):
                    pass
        with worker.worker_lock(lock):
            pass


if __name__ == "__main__":
    unittest.main()
