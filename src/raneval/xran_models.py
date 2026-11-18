"""Fresh endpoint models for the released XRan 520-column feature layout.

This module deliberately has no dependency on the historical streaming models.
The serialized columns are a feature layout, not an event timeline.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
from pathlib import Path

import numpy as np
import torch
from torch import nn


BUNDLE_SCHEMA = "xran-endpoint-bundle-v1"
FEATURE_WIDTH = 520


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def atomic_torch(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("wb") as stream:
        torch.save(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def model_config(kind, vocab_size, view="all"):
    if kind not in {"counts", "cnn", "gru"}:
        raise ValueError("Unknown XRan endpoint model")
    if view not in {"all", "api", "missingness"}:
        raise ValueError("Unknown feature view")
    if view == "missingness" and kind != "counts":
        raise ValueError("Missingness diagnostic uses a linear counts model")
    if not isinstance(vocab_size, int) or vocab_size < 2:
        raise ValueError("Vocabulary must contain PAD=0 and UNK=1")
    return {
        "kind": kind, "view": view, "vocab_size": vocab_size,
        "width": FEATURE_WIDTH, "pad_id": 0, "unk_id": 1,
        "embedding_dim": 64, "hidden_dim": 64, "dropout": 0.2,
        "cnn_channels": [64, 64], "cnn_kernels": [5, 3],
        "cnn_pool": 2, "cnn_readout": "flatten",
        "gru_layers": 1, "gru_readout": "final_hidden_all_520_positions",
        "counts_transform": "log1p_counts_ignore_PAD_include_UNK",
        "missingness_transform": "blank_fraction_per_view",
    }


class EndpointModel(nn.Module):
    def __init__(self, config):
        super().__init__()
        self.config = dict(config)
        self.kind, self.view = config["kind"], config["view"]
        self.vocab_size = config["vocab_size"]
        if self.kind == "counts":
            self.head = nn.Linear(3 if self.view == "missingness" else self.vocab_size - 1, 1)
        else:
            self.embedding = nn.Embedding(self.vocab_size, 64, padding_idx=0)
            if self.kind == "cnn":
                self.convolution = nn.Sequential(
                    nn.Conv1d(64, 64, 5, padding=2), nn.ReLU(), nn.MaxPool1d(2),
                    nn.Dropout(0.2), nn.Conv1d(64, 64, 3, padding=1),
                    nn.ReLU(), nn.MaxPool1d(2), nn.Dropout(0.2),
                )
                self.head = nn.Sequential(nn.Linear(64 * 130, 64), nn.ReLU(), nn.Dropout(0.2), nn.Linear(64, 1))
            else:
                self.recurrent = nn.GRU(64, 64, batch_first=True)
                self.head = nn.Sequential(nn.Dropout(0.2), nn.Linear(64, 1))

    def forward(self, tokens):
        if self.view == "api":
            tokens = torch.cat((tokens[:, :500], torch.zeros_like(tokens[:, 500:])), dim=1)
        if self.kind == "counts":
            if self.view == "missingness":
                features = torch.stack([(tokens[:, start:end] == 0).float().mean(dim=1)
                                        for start, end in ((0, 500), (500, 510), (510, 520))], dim=1)
            else:
                counts = torch.zeros((tokens.shape[0], self.vocab_size), device=tokens.device, dtype=torch.float32)
                counts.scatter_add_(1, tokens, torch.ones_like(tokens, dtype=torch.float32))
                features = counts[:, 1:].log1p()
            return self.head(features).squeeze(1)
        embedded = self.embedding(tokens)
        if self.kind == "cnn":
            features = self.convolution(embedded.transpose(1, 2)).flatten(1)
        else:
            # No packing or skipping PAD positions: every fixed column advances state.
            _, final_hidden = self.recurrent(embedded)
            features = final_hidden[-1]
        return self.head(features).squeeze(1)


def build_model(config):
    expected = model_config(config.get("kind"), config.get("vocab_size"), config.get("view", "all"))
    if config != expected:
        raise ValueError("Unsupported or incomplete XRan architecture configuration")
    return EndpointModel(config)


def validate_tokens(tokens, vocab_size):
    array = np.asarray(tokens)
    if array.ndim != 2 or array.shape[1] != FEATURE_WIDTH or array.dtype.kind not in "iu":
        raise ValueError("Expected integer encoded rows with shape [N,520]")
    if array.size and (array.min() < 0 or array.max() >= vocab_size):
        raise ValueError("Encoded token outside bundle vocabulary")
    return np.asarray(array, dtype=np.int64)


def predict_endpoint(encoded_rows, frozen_bundle, batch_size=128):
    """Return actual float32 torch sigmoid results losslessly as binary64.

    The caller must bind runtime/device/batch settings when calibrating. Serving
    and final evaluation use CPU batch size 1; tune scoring may use larger batches.
    """
    if batch_size < 1:
        raise ValueError("batch_size must be positive")
    model = frozen_bundle["model"]
    values = validate_tokens(encoded_rows, model.vocab_size)
    device = next(model.parameters()).device
    scores = []
    model.eval()
    with torch.inference_mode():
        for start in range(0, len(values), batch_size):
            batch = torch.from_numpy(values[start:start + batch_size].copy()).to(device)
            probability = torch.sigmoid(model(batch).float()).cpu().numpy()
            scores.append(probability.astype(np.float64))
    result = np.concatenate(scores) if scores else np.empty(0, dtype=np.float64)
    if not np.isfinite(result).all() or ((result < 0) | (result > 1)).any():
        raise ValueError("Endpoint model emitted an invalid probability")
    return result


def export_bundle(out_dir, model, config, vocabulary, provenance):
    """Export tensors plus a checked JSON manifest; return manifest metadata."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    if config != model.config or config != model_config(config["kind"], config["vocab_size"], config["view"]):
        raise ValueError("Exported model and architecture configuration disagree")
    if vocabulary.get("schema") != "xran-vocabulary-v1" or vocabulary.get("size") != config["vocab_size"]:
        raise ValueError("Bundle vocabulary does not match architecture")
    if vocabulary.get("pad_id") != 0 or vocabulary.get("unk_id") != 1:
        raise ValueError("Bundle vocabulary has incompatible special tokens")
    atomic_torch(out_dir / "weights.pt", {key: value.detach().cpu() for key, value in model.state_dict().items()})
    atomic_json(out_dir / "vocabulary.json", vocabulary)
    metadata = {
        "schema": BUNDLE_SCHEMA, "task": "ransomware_vs_benign",
        "unit": "unique_released_feature_vector", "config": config,
        "normalization": "exact_strings_namespaced_by_view; blank=PAD0; unknown=UNK1",
        "weights_sha256": digest(out_dir / "weights.pt"),
        "vocabulary_sha256": digest(out_dir / "vocabulary.json"),
        "model_source_sha256": digest(__file__),
        "software": {"torch": str(torch.__version__), "numpy": np.__version__, "python": platform.python_version()},
        "score_arithmetic": "torch_float32_logit_then_float32_sigmoid_converted_losslessly_to_binary64",
        "provenance": provenance,
    }
    atomic_json(out_dir / "bundle.json", metadata)
    return metadata


def load_bundle(path, device="cpu"):
    path = Path(path)
    manifest_path = path if path.is_file() else path / "bundle.json"
    directory = manifest_path.parent
    metadata = json.loads(manifest_path.read_text(encoding="utf-8"))
    if metadata.get("schema") != BUNDLE_SCHEMA:
        raise ValueError("Not an XRan endpoint bundle; streaming bundles are incompatible")
    for name, key in (("weights.pt", "weights_sha256"), ("vocabulary.json", "vocabulary_sha256")):
        if digest(directory / name) != metadata.get(key):
            raise ValueError(f"XRan bundle checksum mismatch: {name}")
    vocabulary = json.loads((directory / "vocabulary.json").read_text(encoding="utf-8"))
    config = metadata["config"]
    if vocabulary.get("schema") != "xran-vocabulary-v1" or vocabulary.get("size") != config["vocab_size"]:
        raise ValueError("XRan bundle vocabulary mismatch")
    if vocabulary.get("pad_id") != 0 or vocabulary.get("unk_id") != 1:
        raise ValueError("XRan bundle special token mismatch")
    model = build_model(config)
    model.load_state_dict(torch.load(directory / "weights.pt", map_location="cpu", weights_only=True), strict=True)
    if hasattr(model, "embedding") and torch.count_nonzero(model.embedding.weight[0]).item():
        raise ValueError("XRan PAD embedding must remain exactly zero")
    if any(not torch.isfinite(value).all() for value in model.state_dict().values()):
        raise ValueError("XRan bundle contains nonfinite weights")
    model.to(device).eval()
    return {"model": model, "metadata": metadata, "vocabulary": vocabulary,
            "path": directory, "bundle_sha256": digest(manifest_path)}
