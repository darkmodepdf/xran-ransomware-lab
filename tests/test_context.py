import unittest

from raneval.context import CONTEXT_FEATURE_NAMES, ContextState, context_rows


def event(op, file="one", directory="logs", actor="service", size=None):
    return {"op": op, "actor": actor, "file": file, "directory": directory, "bytes_changed": size}


class ContextTests(unittest.TestCase):
    def test_distinguishes_repeated_changes_from_spread_at_same_opcodes(self):
        repeated = [event("read"), event("write", size=40), event("write", size=40)]
        spread = [event("read"), event("write", size=40),
                  event("write", file="two", directory="work", size=40)]
        narrow = dict(zip(CONTEXT_FEATURE_NAMES, context_rows(repeated, 256)[-1]))
        broad = dict(zip(CONTEXT_FEATURE_NAMES, context_rows(spread, 256)[-1]))
        self.assertEqual(narrow["actor_repeated_file_change"], 1)
        self.assertEqual(narrow["actor_changed_recently_read_file"], 1)
        self.assertEqual(broad["actor_changed_new_file"], 1)
        self.assertLess(narrow["recent_actor_change_directory_diversity"],
                        broad["recent_actor_change_directory_diversity"])
        self.assertEqual(narrow["write_size"], broad["write_size"])

    def test_prefix_stability_and_block_reset(self):
        events = [event("write", size=9), event("read"), event("write", size=9),
                  event("write", actor="helper", size=8)]
        rows = context_rows(events, 2)
        self.assertEqual(context_rows(events[:3], 2), rows[:3])
        self.assertEqual(rows[0], rows[2])
        self.assertEqual(rows[2], context_rows(events[2:3], 2)[0])
        state = ContextState(2)
        self.assertEqual(rows, [state.step(item) for item in events])

    def test_opaque_ids_and_missing_context(self):
        events = [event("read"), event("write", size=5)]
        renamed = [event("read", "42", "3", "99"), event("write", "42", "3", "99", 5)]
        self.assertEqual(context_rows(events, 256), context_rows(renamed, 256))
        self.assertEqual(ContextState().step(event("read", actor=None)),
                         [0.0] * len(CONTEXT_FEATURE_NAMES))
        with self.assertRaises(ValueError):
            ContextState().step(event("open", size=20))
