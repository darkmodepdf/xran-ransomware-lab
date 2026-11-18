"""Score a contextual GRU on ordered, projected Linux observations."""

import hashlib
import math

import torch
from torch import nn

from .context import CONTEXT_FEATURE_NAMES, ContextState
from .core import SequenceModel


class ContextGRU(nn.Module):
    """The frozen token model with a learned linear correction from context."""

    def __init__(self, base, context_weight, max_suppression=None, gate="all"):
        super().__init__()
        if len(CONTEXT_FEATURE_NAMES) != context_weight.numel() or context_weight.ndim != 1:
            raise ValueError("Wrong contextual weight shape")
        if max_suppression is not None and (not math.isfinite(max_suppression) or max_suppression <= 0):
            raise ValueError("Expected a finite positive logit suppression limit")
        if gate not in {"all", "concentrated", "repeat"} or gate != "all" and max_suppression is None:
            raise ValueError("Unsupported context gate")
        self.base = base
        self.register_buffer("context_weight", context_weight)
        self.max_suppression = max_suppression
        self.gate = gate

    def correction(self, rows):
        logits = (rows * self.context_weight).sum(dim=-1)
        if self.max_suppression is None:
            return logits
        logits = logits.clamp(min=-self.max_suppression, max=0.0)
        if self.gate == "concentrated":
            file_diversity = rows[..., CONTEXT_FEATURE_NAMES.index("recent_actor_change_file_diversity")]
            directory_diversity = rows[..., CONTEXT_FEATURE_NAMES.index("recent_actor_change_directory_diversity")]
            change_share = rows[..., CONTEXT_FEATURE_NAMES.index("recent_actor_change_share")]
            supported = (file_diversity > 0) & (file_diversity <= 0.67) & (directory_diversity > 0)
            supported &= (directory_diversity <= 0.6) & (change_share >= 0.15)
            logits = torch.where(supported, logits, 0.0)
        elif self.gate == "repeat":
            repeated_change = rows[..., CONTEXT_FEATURE_NAMES.index("actor_repeated_file_change")]
            logits = torch.where(repeated_change > 0, logits, 0.0)
        return logits

    def forward(self, tokens, rows):
        return self.base(tokens) + self.correction(rows)


def load_context_bundle(path, device, expected_sha256=None):
    with path.open("rb") as stream:
        checksum = hashlib.file_digest(stream, "sha256").hexdigest()
    if expected_sha256 is not None and checksum != expected_sha256:
        raise ValueError("Context bundle checksum does not match the frozen manifest")
    bundle = torch.load(path, map_location="cpu", weights_only=True)
    if bundle.get("version") != 2 or bundle.get("architecture") != "gru":
        raise ValueError("Unsupported contextual GRU bundle")
    context = bundle["context"]
    if context.get("version") != 1 or tuple(context["feature_names"]) != tuple(CONTEXT_FEATURE_NAMES):
        raise ValueError("Context feature contract does not match the frozen bundle")
    weight = context["weight"]
    if not isinstance(weight, torch.Tensor) or weight.dtype != torch.float32 or not weight.isfinite().all().item():
        raise ValueError("Expected finite float32 context weights")
    base = SequenceModel("gru", len(bundle["vocabulary"]) + 2)
    base.load_state_dict(bundle["state_dict"])
    model = ContextGRU(base, weight, context.get("max_suppression"), context.get("gate", "all"))
    return bundle, model.to(device).eval(), checksum


@torch.inference_mode()
def score_context_blocks(model, tokens, rows, block_size, device):
    """Score context rows prepared from the same reset-bounded operation stream."""
    if len(tokens) != len(rows):
        raise ValueError("Context and operation counts differ")
    model.eval()
    for start in range(0, len(tokens), block_size):
        block = torch.as_tensor(tokens[start:start + block_size], dtype=torch.int64, device=device).unsqueeze(0)
        context = torch.as_tensor(rows[start:start + block_size], dtype=torch.float32, device=device).unsqueeze(0)
        logits = model(block, context)[0]
        if not logits.isfinite().all().item():
            raise ValueError("Model produced a nonfinite logit")
        yield from logits.double().sigmoid().tolist()


class ContextStreamingScorer:
    """Consume one event at a time, resetting context and recurrent state together."""

    def __init__(self, bundle, model, device):
        self.bundle = bundle
        self.model = model.eval()
        self.device = device
        self.positions = 0
        self.state = ContextState(bundle['block_size'])
        self.hidden = None

    @torch.inference_mode()
    def step(self, event):
        if self.bundle["horizon"] and self.positions >= self.bundle["horizon"]:
            raise ValueError("Observation exceeds the frozen replay horizon")
        if self.positions % self.bundle["block_size"] == 0:
            self.hidden = None
        row = self.state.step(event)
        api = event["op"]
        token = self.bundle["vocabulary"].get(api, 1)
        token = torch.tensor([[token]], dtype=torch.int64, device=self.device)
        context = torch.tensor(row, dtype=torch.float32, device=self.device)
        base = self.model.base
        state, self.hidden = base.gru(base.embedding(token), self.hidden)
        logit = base.head(state) + self.model.correction(context)
        self.positions += 1
        if not logit.isfinite().item():
            raise ValueError("Model produced a nonfinite logit")
        return logit.double().sigmoid().item()
