"""Causal file and process features for completed Linux system calls."""

import math
from collections import deque


CONTEXT_FEATURE_NAMES = (
    "recent_actor_file_diversity",
    "recent_actor_change_file_diversity",
    "recent_actor_change_directory_diversity",
    "recent_actor_change_share",
    "actor_recent_event_share",
    "actor_changed_new_file",
    "actor_changed_recently_read_file",
    "actor_repeated_file_change",
    "write_size",
    "recent_actor_write_size",
)

_OPERATIONS = frozenset({"open", "read", "write", "close", "rename", "unlink", "truncate"})
_CHANGE_OPERATIONS = frozenset({"rename", "unlink", "truncate"})
_LOOKBACK = 32
_MAX_LOG_WRITE_SIZE = math.log2(1 + 1024 * 1024)


def _identity(event, key):
    value = event.get(key)
    if value is not None and (not isinstance(value, str) or not value):
        raise ValueError(f"{key} must be a nonempty opaque string or null")
    return value


def _write_size(size):
    return min(math.log2(1 + size) / _MAX_LOG_WRITE_SIZE, 1.0)


class ContextState:
    """Build features from a short rolling history within each GRU block."""

    def __init__(self, block_size=256):
        if type(block_size) is not int or block_size < 1:
            raise ValueError("block_size must be a positive integer")
        self.block_size = block_size
        self.position = 0
        self.recent = deque(maxlen=_LOOKBACK)

    def step(self, event):
        op = event.get("op")
        if op not in _OPERATIONS:
            raise ValueError(f"Unsupported file operation {op!r}")
        actor = _identity(event, "actor")
        file = _identity(event, "file")
        directory = _identity(event, "directory")
        written = event.get("bytes_changed")
        if written is not None and (op != "write" or type(written) is not int or written < 0):
            raise ValueError("bytes_changed must be a nonnegative write result or null")

        if self.position % self.block_size == 0:
            self.recent.clear()
        self.position += 1
        change = op in _CHANGE_OPERATIONS or (op == "write" and (written or 0) > 0)
        size = _write_size(written) if written is not None else None
        prior = [entry for entry in self.recent if actor is not None and entry[0] == actor]
        self.recent.append((actor, op, file, directory, change, size))
        if actor is None:
            return [0.0] * len(CONTEXT_FEATURE_NAMES)

        activity = [entry for entry in self.recent if entry[0] == actor]
        targets = [entry[2] for entry in activity if entry[2] is not None]
        changes = [entry for entry in activity if entry[4]]
        changed_files = [entry[2] for entry in changes if entry[2] is not None]
        changed_dirs = [entry[3] for entry in changes if entry[3] is not None]
        writes = [entry[5] for entry in activity if entry[5] is not None]
        prior_file = [entry for entry in prior if file is not None and entry[2] == file]
        known_actor_events = sum(entry[0] is not None for entry in self.recent)
        return [
            len(set(targets)) / max(1, len(targets)),
            len(set(changed_files)) / max(1, len(changed_files)),
            len(set(changed_dirs)) / max(1, len(changed_dirs)),
            len(changes) / len(activity),
            len(activity) / known_actor_events,
            float(change and file is not None and not any(entry[4] for entry in prior_file)),
            float(change and any(entry[1] == "read" for entry in prior_file)),
            float(change and any(entry[4] for entry in prior_file)),
            size or 0.0,
            sum(writes) / max(1, len(writes)),
        ]


def context_rows(events, block_size):
    state = ContextState(block_size=block_size)
    return [state.step(event) for event in events]
