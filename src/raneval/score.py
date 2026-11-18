"""Replay the exported defensive model on one ordered API-name JSONL stream."""

import argparse
import hashlib
import json
from pathlib import Path

import torch
import torch.nn.functional as F

from .core import SequenceModel, encode, score_blocks


def load_bundle(path, device, expected_sha256=None):
    with path.open("rb") as stream:
        checksum = hashlib.file_digest(stream, "sha256").hexdigest()
    if expected_sha256 is not None and checksum != expected_sha256:
        raise ValueError("Bundle checksum does not match the frozen manifest")
    bundle = torch.load(path, map_location="cpu", weights_only=True)
    if bundle.get("version") != 1:
        raise ValueError("Unsupported inference bundle version")
    model = SequenceModel(bundle["architecture"], len(bundle["vocabulary"]) + 2)
    model.load_state_dict(bundle["state_dict"])
    return bundle, model.to(device).eval(), checksum


def read_apis(path):
    apis = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            api = json.loads(line)
            if not isinstance(api, str) or not api.strip():
                raise ValueError(f"API line {line_number} must be a nonempty JSON string")
            apis.append(api)
    return apis


class StreamingScorer:
    """Score only the API name supplied and preceding observations in the reset block."""

    def __init__(self, bundle, model, device):
        self.bundle = bundle
        self.model = model.eval()
        self.device = device
        self.positions = 0

    def reset_block(self):
        self.hidden = None
        self.pool = None
        self.total = None
        if self.model.architecture == "cnn":
            self.inputs = self.model.embedding.weight.new_zeros((1, 64, 4))
            self.first_layer = self.inputs.new_zeros(self.inputs.shape)

    @torch.inference_mode()
    def step(self, api):
        if not isinstance(api, str) or not api.strip():
            raise ValueError("An observation must be a nonempty API name")
        if self.bundle["horizon"] and self.positions >= self.bundle["horizon"]:
            raise ValueError("Observation exceeds the frozen replay horizon")
        if self.positions % self.bundle["block_size"] == 0:
            self.reset_block()
        token = self.bundle["vocabulary"].get(api, 1)
        model = self.model
        if model.architecture == "counts":
            contribution = model.coefficient[token]
            self.total = contribution if self.total is None else self.total + contribution
            logit = self.total + model.bias
        else:
            embedded = model.embedding(torch.tensor([[token]], device=self.device))
            if model.architecture == "cnn":
                inputs = torch.cat((self.inputs, embedded.transpose(1, 2)), dim=-1)
                first = torch.cat((self.first_layer, F.relu(model.conv1(inputs))), dim=-1)
                state = F.relu(model.conv2(first)).squeeze(-1)
                self.inputs = inputs[..., 1:]
                self.first_layer = first[..., 1:]
                self.pool = state if self.pool is None else torch.maximum(self.pool, state)
                logit = model.head(self.pool)
            else:
                state, self.hidden = model.gru(embedded, self.hidden)
                logit = model.head(state)
        self.positions += 1
        if not logit.isfinite().all().item():
            raise ValueError("Model produced a nonfinite logit")
        return logit.double().sigmoid().item()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--apis", type=Path, required=True, help="A JSON string per line, one retained API record per observation.")
    parser.add_argument("--output", type=Path, required=True, help="New score JSONL, with an adjacent .meta.json manifest.")
    parser.add_argument("--device", choices=("cpu", "cuda"), default="cpu")
    parser.add_argument("--alpha", type=float, default=0.05)
    parser.add_argument("--expected-sha256", help="Expected inference bundle checksum from frozen.json.")
    args = parser.parse_args(argv)
    torch.set_num_threads(1)
    device = torch.device(args.device)
    bundle, model, checksum = load_bundle(args.bundle, device, args.expected_sha256)
    thresholds = [threshold for threshold in bundle["thresholds"] if threshold["alpha"] == args.alpha]
    if len(thresholds) != 1:
        raise ValueError(f"Bundle has no unique frozen threshold for alpha={args.alpha}")
    threshold = thresholds[0]
    with args.apis.open("rb") as stream:
        api_trace_sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
    apis = read_apis(args.apis)
    tokens = encode(apis, bundle["vocabulary"], bundle["horizon"])
    metadata_path = args.output.with_suffix(args.output.suffix + ".meta.json")
    if args.output.exists() or metadata_path.exists():
        raise FileExistsError("Score output or its metadata already exists")
    tau = threshold["tau"]
    alert = None
    with args.output.open("x", encoding="utf-8") as stream:
        for position, score in enumerate(score_blocks(model, tokens, bundle["block_size"], device), 1):
            if alert is None and tau is not None and score >= tau:
                alert = position
            stream.write(json.dumps({"observation_index": position, "score": score}, allow_nan=False) + "\n")
    with metadata_path.open("x", encoding="utf-8") as stream:
        json.dump({"bundle_sha256": checksum, "api_trace_sha256": api_trace_sha256,
                   "architecture": bundle["architecture"], "threshold": threshold,
                   "first_observation": alert, "observed_horizon": len(tokens), "device": args.device}, stream,
                  indent=2, allow_nan=False)
        stream.write("\n")


if __name__ == "__main__":
    main()
