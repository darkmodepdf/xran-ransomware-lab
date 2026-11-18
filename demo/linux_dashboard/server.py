"""Serve a local dashboard for replaying frozen Linux detector fixtures."""

import argparse
import hashlib
import json
import math
import os
import platform
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import numpy as np
import onnxruntime as ort

from model_adapter import read_trace
from runner import run_pair


STATIC = Path(__file__).with_name("static")
ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/comparison.js": ("comparison.js", "text/javascript; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
}
BENCHMARK_SCHEMA = "raneval-linux-benchmark-v1"
REQUIRED_SCENARIOS = ("ransomware", "benign")
SCENARIO_LABELS = {"ransomware": "Ransomware trace", "benign": "Benign control",
                   "illustrative": "Early-alert illustration"}
RATES = (5, 20, 100, 0)
MAX_OBSERVATIONS = 1024


def read_object(path):
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain an object")
    return value


def check_digest(value, label):
    if not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{64}", value) is None:
        raise ValueError(f"Invalid SHA-256 for {label}")
    return value


class Dashboard:
    def __init__(self, inputs):
        self.benchmark_path = inputs / "benchmark.json"
        frozen = read_object(inputs / "frozen.json")
        manifest = read_object(inputs / "manifest.json")
        threshold, = (entry for entry in frozen["thresholds"] if entry["alpha"] == manifest["alpha"])
        tau = threshold["tau"]
        if tau is not None and (type(tau) not in (int, float) or not 0 <= tau <= 1):
            raise ValueError("Invalid frozen threshold")
        self.block_size = frozen["block_size"]
        horizon = frozen["horizon"]
        if type(self.block_size) is not int or self.block_size < 1 or type(horizon) is not int or horizon < 0:
            raise ValueError("Invalid frozen replay limits")
        self.vocabulary = frozen["vocabulary"]
        if not self.vocabulary or any(type(token) is not int or token < 2 for token in self.vocabulary.values()):
            raise ValueError("Invalid frozen vocabulary")

        bundle_digest = check_digest(frozen["bundle_sha256"], "training bundle")
        model_digest = check_digest(frozen["onnx_sha256"], "ONNX model")
        model_bytes = (inputs / "model.onnx").read_bytes()
        if hashlib.sha256(model_bytes).hexdigest() != model_digest:
            raise ValueError("ONNX model does not match its frozen SHA-256")
        options = ort.SessionOptions()
        options.intra_op_num_threads = 1
        options.inter_op_num_threads = 1
        self.session = ort.InferenceSession(model_bytes, sess_options=options, providers=["CPUExecutionProvider"])

        self.traces = {}
        fixtures = {}
        scenarios = REQUIRED_SCENARIOS
        if "illustrative" in manifest["fixtures"]:
            scenarios += ("illustrative",)
        for scenario in scenarios:
            fixture = manifest["fixtures"][scenario]
            trace, digest = read_trace(inputs / f"{scenario}.jsonl", min(horizon or MAX_OBSERVATIONS, MAX_OBSERVATIONS))
            if digest != check_digest(fixture["sha256"], f"{scenario} fixture"):
                raise ValueError(f"{scenario} fixture does not match its frozen SHA-256")
            if any(event not in self.vocabulary for event in trace):
                raise ValueError(f"{scenario} fixture includes an event outside the frozen vocabulary")
            expected = fixture.get("first_alert_observation")
            if expected is not None and (type(expected) is not int or not 1 <= expected <= len(trace)):
                raise ValueError(f"Invalid expected alert for {scenario} fixture")
            self.traces[scenario] = trace
            fixtures[scenario] = {**fixture, "count": len(trace), "label": SCENARIO_LABELS[scenario]}

        self.metadata = {
            "source": manifest["source"], "threshold": tau, "alpha": manifest["alpha"],
            "architecture": frozen["architecture"], "block_size": self.block_size,
            "bundle_sha256": bundle_digest, "onnx_sha256": model_digest, "fixtures": fixtures,
            "os": platform.system(), "runtime": "ONNX Runtime CPU", "rates": RATES,
        }
        self.replay_lock = threading.Lock()

    def score(self, block):
        logits, = self.session.run(["logits"], {"tokens": np.asarray([block], dtype=np.int64)})
        logit = float(logits[0, -1])
        if not math.isfinite(logit):
            raise ValueError("The model returned a nonfinite endpoint logit")
        term = math.exp(-abs(logit))
        return term / (1 + term) if logit < 0 else 1 / (1 + term)

    def replay(self, scenario, rate, send):
        observations = self.traces[scenario]
        fixture = self.metadata["fixtures"][scenario]
        threshold = self.metadata["threshold"]
        block = []
        replay_started_ns = None
        replay_elapsed_ms = None

        def observe(event):
            nonlocal replay_started_ns
            if replay_started_ns is None:
                replay_started_ns = time.perf_counter_ns()
            if len(block) == self.block_size:
                block.clear()
            block.append(self.vocabulary[event])
            return self.score(block)

        def on_step(index, score, blocked, alert_now):
            nonlocal replay_elapsed_ms
            if index == len(observations):
                replay_elapsed_ms = (time.perf_counter_ns() - replay_started_ns) / 1_000_000
            send({"kind": "step", "index": index, "operation": observations[index - 1],
                  "score": score, "blocked": blocked, "alert": alert_now})

        send({"kind": "start", "scenario": scenario, "total": len(observations), "rate": rate})
        result = run_pair(observations, threshold, observe=observe, seed=42,
                          delay_ms=1000 / rate if rate else 0, on_step=on_step)
        alert = result["first_alert_observation"]
        if "first_alert_observation" in fixture and alert != fixture["first_alert_observation"]:
            raise RuntimeError("The live alert position differs from the frozen fixture replay")
        monitor = result["monitor_only"]
        protected = result["enforce"]
        initial = result["initial_sha256"]
        rows = [
            {"name": name, "initial_sha256": digest, "monitor_sha256": monitor["final_sha256"][name],
             "protected_sha256": protected["final_sha256"][name]}
            for name, digest in initial.items()
        ]
        if (monitor["modified_files"] != list(initial)
                or protected["modified_files"] != list(initial)[:alert]
                or len(protected["modified_files"]) + result["blocked_writes"] != len(rows)):
            raise RuntimeError("Integrity counts differ from the write-gate outcomes")
        send({"kind": "finish", "first_alert": alert, "alert_elapsed_ms": result["alert_elapsed_ms"],
              "monitor_modified": len(monitor["modified_files"]), "protected_modified": len(protected["modified_files"]),
              "blocked": result["blocked_writes"], "elapsed_ms": replay_elapsed_ms,
              "achieved_eps": 1000 * len(observations) / replay_elapsed_ms, "files": rows})


class Handler(BaseHTTPRequestHandler):
    server_version = "RanEval"

    def respond(self, status, mime_type, length=None):
        self.send_response(status)
        self.send_header("Content-Type", mime_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        if length is not None:
            self.send_header("Content-Length", str(length))
        self.end_headers()

    def json_response(self, status, payload):
        body = json.dumps(payload, allow_nan=False).encode()
        self.respond(status, "application/json; charset=utf-8", len(body))
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/api/metadata":
            self.json_response(200, self.server.dashboard.metadata)
        elif path == "/api/benchmark":
            self.benchmark_response()
        elif path in ASSETS:
            name, mime_type = ASSETS[path]
            body = (STATIC / name).read_bytes()
            self.respond(200, mime_type, len(body))
            self.wfile.write(body)
        else:
            self.json_response(404, {"error": "Unknown dashboard route"})

    def benchmark_response(self):
        try:
            benchmark = read_object(self.server.dashboard.benchmark_path)
            if benchmark.get("schema") != BENCHMARK_SCHEMA:
                raise ValueError("Unsupported benchmark schema")
            self.json_response(200, benchmark)
        except FileNotFoundError:
            self.json_response(404, {"error": "Stage benchmark.json in the input directory to view results."})
        except (OSError, ValueError):
            self.json_response(422, {"error": "The staged benchmark could not be read. Rebuild benchmark.json."})

    def do_POST(self):
        if self.path != "/api/replay":
            self.json_response(404, {"error": "Unknown dashboard route"})
            return
        dashboard = self.server.dashboard
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if self.headers.get_content_type() != "application/json" or not 1 <= length <= 256:
                raise ValueError
            body = json.loads(self.rfile.read(length))
            scenario, rate = body["scenario"], body["rate"]
            if scenario not in dashboard.traces or type(rate) is not int or rate not in RATES:
                raise ValueError
        except (KeyError, ValueError, TypeError):
            self.json_response(400, {"error": "Choose a staged fixture and a supported replay rate"})
            return

        if not dashboard.replay_lock.acquire(blocking=False):
            self.json_response(409, {"error": "A replay is already running"})
            return

        def send(event):
            self.wfile.write((json.dumps(event, allow_nan=False) + "\n").encode())
            self.wfile.flush()

        try:
            self.respond(200, "application/x-ndjson; charset=utf-8")
            dashboard.replay(scenario, rate, send)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass
        except Exception as exc:
            self.log_error("Replay failed: %s", exc)
            try:
                send({"kind": "error", "error": str(exc)})
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass
        finally:
            dashboard.replay_lock.release()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, default=Path("/inputs"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    dashboard = Dashboard(args.inputs)
    with ThreadingHTTPServer((args.host, args.port), Handler) as server:
        server.dashboard = dashboard
        print(f"RanEval on port {server.server_port} · {platform.system()} · PID {os.getpid()}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
