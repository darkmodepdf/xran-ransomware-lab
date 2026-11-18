"""Input, model and replay contracts shared by training and demonstration."""

import hashlib
import json
import math
import random
from dataclasses import dataclass
from pathlib import Path

import torch
import torch.nn.functional as F
from torch import nn


LABELS = {"RANSOMWARE", "BENIGN", "OTHER_MALWARE"}
ROLES = {"train", "tune", "calibrate", "test"}
FRACTIONS = (0.01, 0.05, 0.10, 0.25, 0.50, 1.0)
EARLY_OBSERVATIONS = 120


@dataclass(frozen=True)
class Trace:
    trace_id: str
    label: str
    role: str
    group_id: str
    apis: tuple[str, ...]


def load_traces(path: Path) -> tuple[list[Trace], str]:
    source = hashlib.sha256()
    traces = []
    seen_ids = set()
    groups = {}
    sequence_roles = {}
    with path.open("rb") as stream:
        for line_number, line in enumerate(stream, 1):
            source.update(line)
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError(f"Expected an object on line {line_number}")
            trace_id, label, role, group_id, apis = (
                row.get(key) for key in ("trace_id", "label", "role", "group_id", "apis")
            )
            if not all(isinstance(value, str) and value.strip() for value in (trace_id, group_id, label, role)):
                raise ValueError(f"Missing or invalid identifier/label/role on line {line_number}")
            if label not in LABELS or role not in ROLES:
                raise ValueError(f"Unknown label/role on line {line_number}")
            if role == "calibrate" and label != "BENIGN":
                raise ValueError(f"Calibration is benign-only: {trace_id}")
            if not isinstance(apis, list) or any(not isinstance(api, str) or not api.strip() for api in apis):
                raise ValueError(f"Invalid APIs on line {line_number}")
            if trace_id in seen_ids:
                raise ValueError(f"Duplicate trace_id: {trace_id}")
            if groups.setdefault(group_id, role) != role:
                raise ValueError(f"Group spans roles: {group_id}")
            if apis:
                token_hash = hashlib.sha256(json.dumps(apis, ensure_ascii=False).encode("utf-8")).digest()
                if sequence_roles.setdefault(token_hash, role) != role:
                    raise ValueError(f"Duplicate API sequence crosses roles: {trace_id}")
            traces.append(Trace(trace_id, label, role, group_id, tuple(apis)))
            seen_ids.add(trace_id)
    return traces, source.hexdigest()


def train_vocabulary(traces: list[Trace], horizon: int) -> dict[str, int]:
    known = {api for trace in traces if trace.role == "train" for api in trace.apis[:horizon or None]}
    # 0 and 1 are reserved for padding and unknown observations.
    return {api: index for index, api in enumerate(sorted(known), 2)}


def encode(apis, vocabulary, horizon=0):
    return [vocabulary.get(api, 1) for api in apis[:horizon or None]]


def sample_endpoints(length: int, limit: int, rng: random.Random) -> list[int]:
    if length <= limit:
        return list(range(1, length + 1))
    early_count = (limit + 1) // 2
    positions = {round(math.exp(math.log(length) * i / max(early_count - 1, 1))) for i in range(early_count)}
    while len(positions) < limit:
        positions.add(rng.randint(1, length))
    return sorted(positions)


def sample_early_endpoints(length: int, limit: int, rng: random.Random) -> list[int]:
    """Sample unique trace-relative endpoints with additional coverage through observation 120."""
    if length <= limit:
        return list(range(1, length + 1))
    if limit == 1:
        return [1]
    buckets = (
        range(2, min(EARLY_OBSERVATIONS, length) + 1),
        range(EARLY_OBSERVATIONS + 1, min(256, length) + 1),
        range(257, min(512, length) + 1),
        range(513, length + 1),
    )
    # Observation 1 is fixed. At the default limit of 16, complete traces
    # receive 8, 3, 2 and 3 endpoints across the four buckets, respectively.
    schedule = (1, 2, 3, 0, 0, 1, 0, 2, 0, 3, 0, 1, 0, 3, 0)
    counts = [0] * len(buckets)
    allocated = 1
    while allocated < limit:
        for index in schedule:
            if counts[index] < len(buckets[index]):
                counts[index] += 1
                allocated += 1
                if allocated == limit:
                    break
    return sorted([1, *(position for bucket, count in zip(buckets, counts) for position in rng.sample(bucket, count))])


class SequenceModel(nn.Module):
    def __init__(self, architecture: str, vocabulary_size: int):
        super().__init__()
        self.architecture = architecture
        if architecture == "counts":
            self.coefficient = nn.Parameter(torch.zeros(vocabulary_size, dtype=torch.float64))
            self.bias = nn.Parameter(torch.zeros((), dtype=torch.float64))
            return
        self.embedding = nn.Embedding(vocabulary_size, 64, padding_idx=0)
        if architecture == "cnn":
            self.conv1 = nn.Conv1d(64, 64, 5)
            self.conv2 = nn.Conv1d(64, 64, 5)
            self.dropout = nn.Dropout(0.1)
            self.head = nn.Sequential(nn.Linear(64, 64), nn.ReLU(), nn.Linear(64, 1))
        elif architecture == "gru":
            self.gru = nn.GRU(64, 128, batch_first=True)
            self.head = nn.Linear(128, 1)
        else:
            raise ValueError(f"Unknown architecture {architecture}")

    def forward(self, tokens):
        if self.architecture == "counts":
            return self.coefficient[tokens].cumsum(dim=-1) + self.bias
        embedded = self.embedding(tokens)
        if self.architecture == "cnn":
            states = self.dropout(F.relu(self.conv1(F.pad(embedded.transpose(1, 2), (4, 0)))))
            states = F.relu(self.conv2(F.pad(states, (4, 0))))
            states = torch.cummax(states, dim=-1).values.transpose(1, 2)
        else:
            states, _ = self.gru(embedded)
        return self.head(states).squeeze(-1)


@torch.inference_mode()
def score_blocks(model, tokens, block_size, device):
    """Run all causally valid positions of each reset block at once."""
    model.eval()
    for start in range(0, len(tokens), block_size):
        block = torch.tensor(tokens[start:start + block_size], device=device).unsqueeze(0)
        logits = model(block)[0]
        if not logits.isfinite().all().item():
            raise ValueError("Model produced a nonfinite logit")
        yield from logits.double().sigmoid().tolist()


def choose_threshold(maxima, alpha):
    ordered = sorted(maxima, reverse=True)
    if not ordered or any(not math.isfinite(value) or not 0 <= value <= 1 for value in ordered):
        raise ValueError("Calibration requires nonempty finite maxima in [0, 1]")
    if not 0 <= alpha < 1:
        raise ValueError("alpha must be in [0,1)")
    allowed = math.floor(alpha * len(ordered))
    tau = math.nextafter(ordered[allowed], math.inf)
    never_alert = tau > 1
    return {
        "alpha": alpha,
        "mode": "never_alert" if never_alert else "threshold",
        "tau": None if never_alert else tau,
        "n": len(ordered),
        "alerts": 0 if never_alert else sum(value >= tau for value in ordered),
    }


def first_alert(scores, threshold):
    tau = threshold["tau"]
    if tau is None:
        return None
    return next((index for index, score in enumerate(scores, 1) if score >= tau), None)


def earliness(alert, length):
    if alert is None or length == 0:
        return 0.0
    return sum(alert / length <= fraction for fraction in FRACTIONS) / len(FRACTIONS)
