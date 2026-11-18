"""Score concurrent Linux tasks with independent bounded recurrent histories."""

from copy import copy

from .context_score import ContextGRU, ContextStreamingScorer
from .score import StreamingScorer


class ProcessStreamingScorer:
    """Route each event to its actor's scorer while sharing frozen model weights.

    Actor keys must identify a task incarnation within a collection session.
    A bare reusable PID is insufficient for continuous host observation. The
    archived data supplies capture-local task identities and has limited
    lifecycle information, so its guarantees apply within that capture.

    Each actor keeps the bundle's recurrent reset interval and continues past
    the original finite benchmark horizon. Thresholds must be calibrated for
    this routing and the deployment's observation interval and alarm unit.
    """

    def __init__(self, bundle, model, device, max_actors=1024):
        if type(max_actors) is not int or max_actors < 1:
            raise ValueError("max_actors must be a positive integer")
        if type(bundle["block_size"]) is not int or bundle["block_size"] < 1:
            raise ValueError("block_size must be a positive integer")
        self.bundle = {**bundle, "horizon": 0}
        self.model = model.eval()
        self.device = device
        self.max_actors = max_actors
        self.positions = 0
        self._actors = {}
        self.contextual = isinstance(model, ContextGRU)

    @property
    def active_actor_count(self):
        return len(self._actors)

    def step(self, event):
        if not isinstance(event, dict):
            raise ValueError("Expected a completed syscall object")
        actor = event.get("actor")
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("A completed syscall requires a nonempty actor identity")
        operation = event.get("op")
        if not isinstance(operation, str) or not operation.strip():
            raise ValueError("A completed syscall requires a nonempty operation")
        scorer = self._actors.get(actor)
        if scorer is None:
            if len(self._actors) >= self.max_actors:
                raise RuntimeError("Active actor limit reached; explicitly retire completed tasks before continuing")
            implementation = ContextStreamingScorer if self.contextual else StreamingScorer
            candidate = implementation(self.bundle, self.model, self.device)
        else:
            # Commit state only after the observation has scored successfully.
            candidate = copy(scorer)
            if self.contextual:
                candidate.state = copy(scorer.state)
                candidate.state.recent = scorer.state.recent.copy()
        score = candidate.step(event if self.contextual else operation)
        self._actors[actor] = candidate
        self.positions += 1
        return {"actor": actor, "actor_event": candidate.positions,
                "stream_event": self.positions, "score": score}

    def retire(self, actor):
        """Release a completed task and return an observable lifecycle record."""
        scorer = self._actors.pop(actor)
        return {"actor": actor, "actor_event": scorer.positions,
                "stream_event": self.positions, "retired": True}
