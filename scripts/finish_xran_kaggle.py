"""Watch one existing Kaggle kernel and publish only its verified XRan evaluation.

Run with the project Python environment. The authenticated Kaggle CLI must be on
PATH. This worker never submits, uploads, trains, or starts a dashboard server.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLL_SECONDS = 30
PENDING = {"queued", "running", "new_script", "cancel_requested"}
FAILURES = {"error", "cancel_acknowledged", "cancelled", "canceled", "failed"}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    checksum = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def atomic_bytes(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + ".", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def atomic_json(path, value):
    atomic_bytes(path, (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8"))


def parse_status(output, kernel):
    """Parse the CLI's exact status line, never words in a failure message."""
    matches = re.findall(r'^' + re.escape(kernel) + r' has status "([^"\r\n]+)"\s*$', output, re.MULTILINE)
    if len(matches) != 1:
        raise ValueError("Expected exactly one Kaggle status line for the requested kernel")
    status = matches[0].rsplit(".", 1)[-1].lower().replace("-", "_")
    if status not in PENDING | FAILURES | {"complete"}:
        raise ValueError(f"Unknown Kaggle kernel status: {status}")
    return status


@contextlib.contextmanager
def worker_lock(path):
    """OS-owned lock automatically releases after exit or a crashed worker."""
    with Path(path).open("a+b") as stream:
        if stream.tell() == 0:
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise RuntimeError("Another completion worker already owns this output directory") from error
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def find_campaign(output_dir):
    markers = sorted(Path(output_dir).rglob("campaign-complete.json"))
    if len(markers) != 1:
        raise ValueError(f"Expected exactly one campaign-complete.json, found {len(markers)}")
    marker = markers[0].resolve()
    if not marker.is_relative_to(Path(output_dir).resolve()):
        raise ValueError("Campaign marker escapes downloaded output directory")
    return marker.parent


def validate_export(evaluation_dir, campaign_dir, data_dir):
    """Require the evaluator's receipt and every completed artifact before exposure."""
    evaluation_dir = Path(evaluation_dir).resolve()
    receipt = json.loads((evaluation_dir / "verification.json").read_text(encoding="utf-8"))
    if receipt.get("schema") != "xran-evaluation-verification-v1" or receipt.get("all_independent_rescores_exact") is not True:
        raise ValueError("Missing successful independent-rescore verification receipt")
    artifacts = receipt.get("artifacts", {})
    if "evaluation.json" not in artifacts:
        raise ValueError("Verification receipt does not bind evaluation.json")
    for name, expected in artifacts.items():
        artifact = (evaluation_dir / name).resolve()
        if not artifact.is_relative_to(evaluation_dir) or digest(artifact) != expected:
            raise ValueError(f"Evaluation artifact checksum mismatch: {name}")
    identity = receipt.get("identity", {})
    if identity.get("campaign_sha256") != digest(Path(campaign_dir) / "campaign-complete.json"):
        raise ValueError("Evaluation receipt belongs to a different campaign")
    if identity.get("data_manifest_sha256") != digest(Path(data_dir) / "manifest.json"):
        raise ValueError("Evaluation receipt belongs to different prepared data")
    spec = importlib.util.spec_from_file_location("xran_dashboard_validation", ROOT / "demo/xran_dashboard/server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    report_path = evaluation_dir / "evaluation.json"
    status, report = module.Dashboard(report_path).read_evaluation()
    if status != 200:
        raise ValueError(report["message"])
    return report_path, artifacts["evaluation.json"]


class Worker:
    def __init__(self, kernel, data_dir, out, timeout_minutes=150, once=False,
                 runner=subprocess.run, sleeper=time.sleep, dashboard_report=None):
        self.kernel = kernel
        self.data_dir = Path(data_dir).resolve()
        self.out = Path(out).resolve()
        self.out.mkdir(parents=True, exist_ok=True)
        self.status_path = self.out / "completion-status.json"
        self.dashboard_report = Path(dashboard_report).resolve() if dashboard_report else self.out / "evaluation.json"
        self.once = once
        self.runner, self.sleeper = runner, sleeper
        self.timeout_minutes = timeout_minutes
        self.state = {}

    def record(self, phase, **values):
        self.state.update(phase=phase, updated_at=utc_now(), pid=os.getpid(), **values)
        atomic_json(self.status_path, self.state)
        event = {"at": self.state["updated_at"], "phase": phase, **values}
        with (self.out / "completion-worker.log").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, ensure_ascii=False, allow_nan=False) + "\n")
            stream.flush()
        print(json.dumps(event, ensure_ascii=False, allow_nan=False), flush=True)

    def remaining(self):
        remaining = self.state["deadline_unix"] - time.time()
        if remaining <= 0:
            raise TimeoutError("Completion-worker deadline reached; no new Kaggle run was submitted")
        return remaining

    def command(self, arguments, timeout_limit, log_name):
        timeout = min(timeout_limit, self.remaining())
        try:
            result = self.runner(arguments, cwd=ROOT, capture_output=True, text=True,
                                 encoding="utf-8", errors="replace", timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise TimeoutError(f"Command timed out after {timeout:.0f}s: {Path(arguments[0]).name}") from error
        output = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
        atomic_bytes(self.out / log_name, output.encode("utf-8"))
        if result.returncode != 0:
            raise RuntimeError(f"Command exited {result.returncode}: {output[-6000:].strip()}")
        return output

    def run(self):
        if self.status_path.exists():
            self.state = json.loads(self.status_path.read_text(encoding="utf-8"))
            if self.state.get("kernel") != self.kernel or self.state.get("data_dir") != str(self.data_dir):
                raise ValueError("Existing worker status belongs to another kernel or prepared-data directory; choose a new --out")
            if self.state.get("dashboard_report", str(self.out / "evaluation.json")) != str(self.dashboard_report):
                raise ValueError("Existing worker status belongs to a different dashboard report path")
        else:
            self.state = {"schema": "xran-completion-worker-v1", "kernel": self.kernel,
                          "data_dir": str(self.data_dir), "out": str(self.out), "started_at": utc_now(),
                          "dashboard_report": str(self.dashboard_report),
                          "deadline_unix": time.time() + self.timeout_minutes * 60,
                          "timeout_minutes": self.timeout_minutes, "poll_interval_seconds": POLL_SECONDS,
                          "poll_count": 0, "download_complete": False}
        if self.state.get("phase") == "complete":
            # A completed restart verifies byte receipts without a network request or model refit.
            try:
                report_path, checksum = validate_export(self.out / "verified-evaluation", find_campaign(self.out / "kaggle-output"), self.data_dir)
                if not self.dashboard_report.exists() or digest(self.dashboard_report) != checksum:
                    atomic_bytes(self.dashboard_report, report_path.read_bytes())
                self.record("complete", evaluation_sha256=checksum, message="Existing completed evaluation verified")
                return 0
            except Exception as error:
                self.record("verification_failed", last_error=f"{type(error).__name__}: {error}")
                return 1
        kaggle = shutil.which("kaggle")
        self.record("resuming" if self.state.get("poll_count") else "starting", last_error=None)
        try:
            if not kaggle:
                raise RuntimeError("Kaggle CLI is not on PATH; run with the configured local environment")
            if not self.state.get("download_complete"):
                while True:
                    self.remaining()
                    try:
                        output = self.command([kaggle, "kernels", "status", self.kernel], 120, "kaggle-status.log")
                        status = parse_status(output, self.kernel)
                    except (RuntimeError, ValueError, TimeoutError) as error:
                        self.record("poll_error", poll_count=self.state["poll_count"] + 1, last_error=str(error))
                        if self.once:
                            return 2
                        self.sleeper(min(POLL_SECONDS, self.remaining()))
                        continue
                    self.record("polling", kernel_status=status, poll_count=self.state["poll_count"] + 1,
                                status_message=output[-4000:].strip(), last_error=None)
                    if status in FAILURES:
                        self.record("kernel_failed", message="Kaggle run ended without successful completion; evaluation was not exposed")
                        return 1
                    if status == "complete":
                        break
                    if self.once:
                        return 0
                    self.sleeper(min(POLL_SECONDS, self.remaining()))
                self.record("downloading", message="Downloading completed Kaggle outputs")
                download_dir = self.out / "kaggle-output"
                download_dir.mkdir(exist_ok=True)
                command = [kaggle, "kernels", "output", self.kernel, "-p", str(download_dir), "--force"]
                output = self.command(command, 1800, "kaggle-download.log")
                # Current CLI downloads all pages automatically. Fail if a CLI instead
                # returns an unconsumed token; never mistake a partial download for success.
                if re.search(r"^Next page token:\s*\S", output, re.MULTILINE):
                    raise ValueError("Kaggle CLI returned an unconsumed output page token; output download is incomplete")
                campaign_dir = find_campaign(download_dir)
                self.record("downloaded", download_complete=True, campaign_dir=str(campaign_dir),
                            campaign_sha256=digest(campaign_dir / "campaign-complete.json"))
            campaign_dir = find_campaign(self.out / "kaggle-output")
            if digest(campaign_dir / "campaign-complete.json") != self.state["campaign_sha256"]:
                raise ValueError("Downloaded campaign marker changed after the completed download")
            evaluation_dir = self.out / "verified-evaluation"
            self.record("evaluating", message="Verifying campaign artifacts, calibrating frozen CPU inference, and evaluating held-out groups")
            self.command([sys.executable, str(ROOT / "scripts/evaluate_xran.py"),
                          "--data-dir", str(self.data_dir), "--campaign-dir", str(campaign_dir),
                          "--out", str(evaluation_dir)], self.remaining(), "evaluation.log")
            report_path, checksum = validate_export(evaluation_dir, campaign_dir, self.data_dir)
            atomic_bytes(self.dashboard_report, report_path.read_bytes())
            self.record("complete", evaluation_path=str(self.dashboard_report),
                        evaluation_sha256=checksum, verification_path=str(evaluation_dir / "verification.json"),
                        message="Verified evaluation is ready for the read-only dashboard", last_error=None)
            return 0
        except TimeoutError as error:
            self.record("timed_out", last_error=str(error))
            return 2
        except Exception as error:
            self.record("failed", last_error=f"{type(error).__name__}: {error}")
            return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", required=True, help="Existing Kaggle owner/kernel-slug; do not repush this slug while watching")
    parser.add_argument("--data-dir", type=Path, default=ROOT / "data/processed/xran-original")
    parser.add_argument("--out", type=Path, default=ROOT / "runs/xran-original")
    parser.add_argument("--dashboard-report", type=Path, help="Publish to an existing dashboard report path")
    parser.add_argument("--timeout-minutes", type=float, default=150)
    parser.add_argument("--once", action="store_true", help="Check status once; if complete, finish download and evaluation")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_-]+/[A-Za-z0-9_-]+", args.kernel):
        parser.error("--kernel must be owner/slug")
    if not 0 < args.timeout_minutes <= 1440:
        parser.error("--timeout-minutes must be in (0,1440]")
    worker = Worker(args.kernel, args.data_dir, args.out, args.timeout_minutes, args.once,
                    dashboard_report=args.dashboard_report)
    try:
        with worker_lock(worker.out / "completion-worker.lock"):
            return worker.run()
    except (OSError, ValueError, RuntimeError) as error:
        # Never replace another worker's status if the lock or identity check failed.
        print(f"Completion worker could not start: {error}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
