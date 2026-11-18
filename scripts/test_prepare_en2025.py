import json
from hashlib import sha256
from importlib.util import find_spec
import os
from pathlib import Path
import tempfile
import unittest

from download_en2025 import ARCHIVES
from prepare_en2025 import (
    SOURCE_RECORD, build_verified_cache_index, decode_report, parse_report, parse_report_stream, prepare, read_report,
)


def report(*streams, sample_hash=None):
    document = {
        "behavior": {"processes": [{"calls": list(stream)} for stream in streams]},
    }
    if sample_hash:
        document["target"] = {"file": {"sha256": sample_hash}}
    return document


class TestPrepareEn2025(unittest.TestCase):
    def test_merges_observed_timestamp_format_and_retains_repeat_as_one(self):
        document = report(
            ({"api": "Open", "timestamp": "2024-12-30 06:47:04,495", "repeated": 8},
             {"api": "Read", "timestamp": "2024-12-30 06:47:04,497"}),
            ({"api": "Close", "timestamp": "2024-12-30 06:47:04,495"},
             {"api": "Query", "timestamp": "2024-12-30 06:47:04,496"}),
        )
        apis, audit = parse_report(document, 3)
        self.assertEqual(apis, ["Open", "Close", "Query"])
        self.assertEqual(audit["api_call_count"], 4)
        self.assertEqual(audit["timestamp_tie_count"], 1)
        self.assertEqual(audit["calls_with_repeat_field"], 1)
        self.assertTrue(audit["horizon_truncated"])

    def test_regressed_clock_keeps_within_process_order_and_changes_quality(self):
        apis, audit = parse_report(report(
            ({"api": "Begin", "time": 9}, {"api": "Finish", "time": 7}),
            ({"api": "Independent", "time": 8},),
        ), 9)
        self.assertEqual(apis, ["Begin", "Finish", "Independent"])
        self.assertEqual(audit["observation_order"], "process_concatenation_unverified")
        self.assertTrue(audit["timestamp_regression_detected"])

    @unittest.skipUnless(find_spec("ijson"), "optional streaming decoder")
    def test_streamed_projection_matches_full_decode(self):
        document = report(
            ({"api": "Open", "timestamp": "2024-12-30 06:47:04,495", "arguments": [["path", "dummy"]],
              "status": False, "return": -1, "repeated": 2},
             {"api": "Read", "timestamp": "2024-12-30 06:47:04,497", "arguments": {"buffer": "dummy"}}),
            ({"api": "Close", "timestamp": "2024-12-30 06:47:04,495", "return_value": None},),
            sample_hash="a" * 64,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_bytes(json.dumps(document).encode())
            self.assertEqual(parse_report_stream(path, 2), parse_report(document, 2))
            document["behavior"]["processes"][0]["calls"].append({"api": ["not a string"]})
            path.write_bytes(json.dumps(document).encode())
            with self.assertRaises(ValueError):
                parse_report_stream(path, 2)

    @unittest.skipUnless(find_spec("orjson"), "optional accelerated decoder")
    def test_numeric_timestamp_uses_exact_decimal_when_fast_decoder_enabled(self):
        document = b'''{"behavior":{"processes":[
            {"calls":[{"api":"B","timestamp":1000000000.0000000002}]},
            {"calls":[{"api":"A","timestamp":1000000000.0000000001}]}
        ]}}'''
        reference = decode_report(document, 3, "stdlib")
        self.assertEqual(reference[0], ["A", "B"])
        self.assertEqual(decode_report(document, 3, "orjson"), reference)

    def test_folder_and_target_hash_conflict_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / ("a" * 64)
            parent.mkdir()
            path = parent / "report.json"
            path.write_text(json.dumps(report(({"api": "A"},), sample_hash="b" * 64)), encoding="utf-8")
            trace = read_report(path, "BENIGN", "report.json", 13, 1024)
            self.assertEqual(trace.audit["status"], "invalid")
            self.assertIn("differs", trace.audit["error"])

    def make_corpus(self, directory):
        roots = []
        for label in ("BENIGN", "RANSOMWARE"):
            root = directory / label
            root.mkdir()
            for i in range(6):
                digest = f"{i + (16 if label == 'BENIGN' else 32):064x}"
                source = report(({"api": f"{label}_fixture_{i}"},), sample_hash=digest)
                (root / f"{i}.json").write_text(json.dumps(source), encoding="utf-8")
            roots.append((label, label, root))
        return roots

    def test_deduplication_conflicts_and_audit_roles_are_deterministic(self):
        with tempfile.TemporaryDirectory() as path:
            directory = Path(path)
            roots = self.make_corpus(directory)
            benign = roots[0][2]
            malicious = roots[1][2]
            duplicate = (benign / "0.json").read_text(encoding="utf-8")
            (benign / "duplicate.json").write_text(duplicate, encoding="utf-8")
            (malicious / "conflict.json").write_text(duplicate, encoding="utf-8")
            output = directory / "training.jsonl"
            audit_path = directory / "audit.json"
            audit = prepare(roots, "*.json", output, audit_path, 130, 16, 20000, False)
            rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(audit["statuses"], {"excluded_cross_label_group": 3, "included": 11})
            self.assertEqual(len({row["group_id"] for row in rows}), len(rows))
            self.assertEqual({row["label"] for row in rows if row["role"] == "calibrate"}, {"BENIGN"})
            again = prepare(roots, "*.json", directory / "second.jsonl", directory / "second-audit.json",
                            130, 16, 20000, False)
            self.assertEqual(again["training_jsonl_sha256"], audit["training_jsonl_sha256"])
            self.assertEqual(again["input_manifest_sha256"], audit["input_manifest_sha256"])

    def test_malformed_report_writes_audit_and_requires_quarantine_flag(self):
        with tempfile.TemporaryDirectory() as path:
            directory = Path(path)
            roots = self.make_corpus(directory)
            (roots[0][2] / "bad.json").write_text('{"behavior":{}}', encoding="utf-8")
            output = directory / "training.jsonl"
            failed = directory / "failed.json"
            with self.assertRaisesRegex(ValueError, "malformed"):
                prepare(roots, "*.json", output, failed, 130, 16, 20000, False)
            self.assertFalse(output.exists())
            self.assertEqual(json.loads(failed.read_text(encoding="utf-8"))["statuses"]["invalid"], 1)
            audit = prepare(roots, "*.json", output, directory / "allowed.json", 130, 16, 20000, True)
            self.assertTrue(output.exists())
            self.assertEqual(audit["statuses"]["invalid"], 1)

    def test_expansion_forces_transitive_prior_groups_to_training(self):
        with tempfile.TemporaryDirectory() as path:
            directory = Path(path)
            roots = self.make_corpus(directory)
            benign = roots[0][2]
            development_member = benign / "0.json"
            development_raw_hash = sha256(development_member.read_bytes()).hexdigest()
            source = report(({"api": "BENIGN_fixture_0"}, {"api": "Extra"}), sample_hash=f"{80:064x}")
            (benign / "prefix-group.json").write_text(json.dumps(source), encoding="utf-8")
            for collection in ("RAT", "SPYWARE"):
                extra_root = directory / collection
                extra_root.mkdir()
                for i in range(4):
                    source = report(({"api": f"{collection}_fixture_{i}"},))
                    (extra_root / f"{i}.json").write_text(json.dumps(source), encoding="utf-8")
                roots.append((collection, "OTHER_MALWARE", extra_root))
            development = directory / "development.json"
            development.write_text(json.dumps({
                "source_record": SOURCE_RECORD, "max_observations": 1,
                "reports": [
                    {"raw_sha256": development_raw_hash},
                    {"source_report": f"ransomware-2/{32:064x}/report.json", "status": "invalid"},
                ],
            }), encoding="utf-8")
            cache = directory / "cache"
            first = prepare(roots, "*.json", directory / "first.jsonl", directory / "first-audit.json",
                            130, 1, 20000, False, development, cache)
            second = prepare(roots, "*.json", directory / "second.jsonl", directory / "second-audit.json",
                             130, 1, 20000, False, development, cache)
            self.assertEqual(first, second)
            protected = [item for item in first["reports"] if item.get("development_group_forced_train")]
            self.assertEqual(len(protected), 3)
            self.assertEqual(sum(item.get("role") == "train" for item in protected), 2)
            self.assertTrue(all(item.get("role") in ("train", None) for item in protected))
            self.assertEqual(first["assignment_counts"]["OTHER_MALWARE"], {"train": 4, "tune": 2, "test": 2})
            self.assertEqual(first["source_assignment_counts"]["RAT"], {"train": 2, "tune": 1, "test": 1})
            self.assertEqual(first["source_assignment_counts"]["SPYWARE"], {"train": 2, "tune": 1, "test": 1})

    def test_verified_extraction_index_has_split_parity_and_falls_back_on_change(self):
        with tempfile.TemporaryDirectory() as path:
            directory = Path(path)
            roots = []
            for source, start in (("benign", 16), ("ransomware", 32)):
                root = directory / source
                inventory = []
                for i in range(5):
                    digest = f"{start + i:064x}"
                    payload = json.dumps(report(({"api": f"{source}_fixture_{i}"},), sample_hash=digest)).encode()
                    parent = root / digest
                    parent.mkdir(parents=True)
                    (parent / "report.json").write_bytes(payload)
                    inventory.append({"member": f"{source}/{digest}/report.json", "status": "extracted_report",
                                      "expanded_bytes": len(payload)})
                size, md5 = ARCHIVES[source]
                (directory / f"{source}-extraction.json").write_text(json.dumps({
                    "source": SOURCE_RECORD, "archive": f"{source}.7z", "archive_bytes": size, "md5": md5,
                    "member_inventory": inventory,
                }), encoding="utf-8")
                roots.append((source.upper(), source.upper(), root))
            cache = directory / "cache"
            original_path = directory / "cold.jsonl"
            fast_path = directory / "fast.jsonl"
            cold = prepare(roots, "*/report.json", original_path, directory / "cold.json",
                           130, 16, 20000, False, cache_dir=cache)
            fast = prepare(roots, "*/report.json", fast_path, directory / "fast.json",
                           130, 16, 20000, False, cache_dir=cache, verified_extraction_cache=True)
            self.assertEqual(cold["identity_lookup_counts"], {"raw_sha256": 10})
            self.assertEqual(fast["identity_lookup_counts"], {"verified_extraction_stat_cache": 10})
            self.assertEqual(original_path.read_bytes(), fast_path.read_bytes())
            index = build_verified_cache_index(roots, cache, 16)
            changed = next(iter(index))
            old = changed.stat()
            os.utime(changed, ns=(old.st_atime_ns, old.st_mtime_ns + 2_000_000_000))
            repeated = read_report(changed, "BENIGN", "changed.json", 16, 20000, cache, verified_entry=index[changed])
            self.assertEqual(repeated.audit["identity_lookup"], "raw_sha256")

            changed.unlink()
            partial_index = build_verified_cache_index(roots, cache, 16)
            self.assertEqual(set(partial_index), set(index) - {changed})
            partial = prepare(roots, "*/report.json", directory / "partial.jsonl", directory / "partial.json",
                              130, 16, 20000, True, cache_dir=cache, verified_extraction_cache=True)
            self.assertEqual(partial["identity_lookup_counts"], {"verified_extraction_stat_cache": 9, "unavailable": 1})
            self.assertEqual(partial["statuses"], {"included": 9, "unavailable_extracted_member": 1})
            unavailable, = (row for row in partial["reports"] if row["status"] == "unavailable_extracted_member")
            self.assertEqual(unavailable["sample_sha256"], changed.parent.name)
            self.assertNotIn("role", unavailable)


if __name__ == "__main__":
    unittest.main()
