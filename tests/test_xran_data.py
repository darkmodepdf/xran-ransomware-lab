from __future__ import annotations

import csv
import hashlib
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from raneval.xran_data import (HEADER, FeatureRow, _largest_remainders, _write_npz,
                               build_groups, encode_views, fingerprint,
                               fit_vocabulary, make_split, read_release, token_key)


def row(identifier, *, source="Benign", label=0, api="Call", dll="", mutex=""):
    cells = [""] * 520
    cells[0], cells[500], cells[510] = api, dll, mutex
    return FeatureRow.create(identifier, source, label, cells)


class XRanDataTests(unittest.TestCase):
    def synthetic_manifest(self, folder, rows, header=None, bom=True, payload=None):
        stream = io.StringIO(newline="")
        writer = csv.writer(stream, delimiter=";", lineterminator="\n")
        writer.writerow(HEADER if header is None else header)
        writer.writerows(rows)
        data = payload if payload is not None else stream.getvalue().encode("utf-8-sig" if bom else "utf-8")
        archive = Path(folder) / "fixture.zip"
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("fixture.csv", data)
        content = archive.read_bytes()
        manifest = {"archives": [{"name": "Benign", "label": 0, "path": archive.name,
                                  "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest(),
                                  "git_blob": hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()}]}
        path = Path(folder) / "manifest.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return path

    def test_semicolon_bom_quoted_newline_and_exact_strings(self):
        cells = [""] * 520
        cells[0:5] = ['semi;colon', 'quoted"value', "line\nvalue", "PRF", "Call"]
        cells[500], cells[501], cells[510] = "Call", "call", " \ufeffvalue "
        with tempfile.TemporaryDirectory() as directory:
            path = self.synthetic_manifest(directory, [cells])
            rows, rejected = read_release(path, require_pinned=False)
        self.assertEqual(rejected, [])
        self.assertEqual(rows[0].cells, tuple(cells))
        self.assertEqual(rows[0].quality["prf_counts"]["api"], 1)
        self.assertEqual(rows[0].quality["empty_counts"]["api"], 495)

    def test_width_rejections_are_counted_and_not_padded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.synthetic_manifest(directory, [[""] * 519, [""] * 521, [""] * 520])
            rows, rejected = read_release(path, require_pinned=False)
        self.assertEqual(len(rows), 1)
        self.assertEqual([item["observed_cells"] for item in rejected], [519, 521])
        self.assertTrue(rows[0].row_id.endswith(":3"))

    def test_bad_header_encoding_integrity_and_unpinned_data_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.synthetic_manifest(directory, [], header=list(reversed(HEADER)))
            with self.assertRaisesRegex(ValueError, "header"):
                read_release(path, require_pinned=False)
            path = self.synthetic_manifest(directory, [], payload=b"\xff")
            with self.assertRaises(UnicodeDecodeError):
                read_release(path, require_pinned=False)
            path = self.synthetic_manifest(directory, [[""] * 520])
            with self.assertRaisesRegex(ValueError, "Unpinned"):
                read_release(path)
            archive = Path(directory) / "fixture.zip"
            content = bytearray(archive.read_bytes())
            content[-1] ^= 1
            archive.write_bytes(content)
            with self.assertRaisesRegex(ValueError, "integrity"):
                read_release(path, require_pinned=False)

    def test_groups_quarantine_both_labels_keep_api_empty_other_views(self):
        rows = [row("z", source="VirusShare", label=1, api="same"),
                row("a", source="ISOT", label=1, api="same"),
                row("c", source="Benign", label=0, api="conflict"),
                row("d", source="ISOT", label=1, api="conflict"),
                row("e", api=""), row("f", api="", dll="present")]
        groups, quarantine = build_groups(rows)
        self.assertEqual((len(groups), len(quarantine)), (2, 2))
        duplicate = next(group for group in groups if group["multiplicity"] == 2)
        self.assertEqual(duplicate["representative_row_id"], "a")
        self.assertEqual(duplicate["sources"], ["ISOT", "VirusShare"])
        self.assertEqual(sum(g["multiplicity"] for g in groups + quarantine), len(rows))
        self.assertTrue(any(g["quality"]["empty_counts"]["api"] == 500 for g in groups))
        self.assertEqual(next(g for g in quarantine if g["label"] is None)["labels"], [0, 1])

    def test_flat_hash_matches_contract_and_differs_from_nested(self):
        values = ["A", "PRF", "é"] + [""] * 517
        expected = hashlib.sha256(json.dumps(values, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(fingerprint(values), expected)
        self.assertNotEqual(fingerprint(values), hashlib.sha256(json.dumps(
            [values[:500], values[500:510], values[510:]], separators=(",", ":")).encode()).hexdigest())

    def test_largest_remainders_exact_ties(self):
        self.assertEqual(_largest_remainders(1), [1, 0, 0, 0])
        self.assertEqual(_largest_remainders(5), [3, 1, 0, 1])
        self.assertEqual(_largest_remainders(10), [6, 1, 1, 2])

    def test_split_deterministic_order_independent_and_all_roles(self):
        rows = [row(f"{label}:{i}", source="Benign" if label == 0 else "ISOT", label=label,
                    api=f"api-{label}-{i}") for label in (0, 1) for i in range(50)]
        groups, _ = build_groups(rows)
        split = make_split(groups)
        self.assertEqual(split, make_split(list(reversed(groups))))
        self.assertEqual(len(split["assignments"]), 100)
        self.assertEqual(split["role_class_counts"], {
            "train": {"0": 30, "1": 30}, "tune": {"0": 5, "1": 5},
            "calibration": {"0": 5, "1": 5}, "test": {"0": 10, "1": 10}})
        with self.assertRaisesRegex(ValueError, "empty"):
            make_split(groups[:1])

    def test_api_components_keep_mixed_labels_and_separate_empty_apis(self):
        rows = [row("a", api="shared", dll="A"),
                row("b", source="ISOT", label=1, api="shared", dll="B"),
                row("c", api="", dll="C"), row("d", api="", dll="D")]
        groups, _ = build_groups(rows)
        split = make_split(groups, api_components=True, require_all_classes=False)
        self.assertEqual(len(split["components"]), 3)
        mixed = [component for component in split["components"] if component["mixed_label"]]
        self.assertEqual(len(mixed), 1)
        self.assertEqual(mixed[0]["labels"], [0, 1])
        self.assertEqual(len({split["assignments"][gid] for gid in mixed[0]["group_ids"]}), 1)
        self.assertEqual(sorted(group["label"] for group in groups), [0, 0, 0, 1])

    def test_train_vocabulary_preserves_namespace_case_prf_and_positions(self):
        train = row("train", api="PRF", dll="PRF", mutex="Case")
        vocabulary = fit_vocabulary([train])
        encoded = encode_views(train, vocabulary)
        test = row("test", api="prf", dll="PRF", mutex="heldout")
        heldout = encode_views(test, vocabulary)
        self.assertNotEqual(encoded[0], encoded[500])
        self.assertEqual(encoded[1], 0)
        self.assertEqual(heldout[0], 1)
        self.assertEqual(heldout[510], 1)
        self.assertEqual(heldout[500], encoded[500])
        self.assertNotIn(token_key("mutex", "heldout"), vocabulary["tokens"])
        self.assertEqual(encoded.shape, (520,))
        self.assertEqual(encoded.dtype, np.int64)

    def test_npz_is_byte_deterministic_and_pickle_free(self):
        arrays = {"tokens": np.array([[0, 1, 2]], dtype=np.int64), "labels": np.array([1], dtype=np.uint8)}
        with tempfile.TemporaryDirectory() as directory:
            first, second = Path(directory) / "first.npz", Path(directory) / "second.npz"
            _write_npz(first, arrays)
            _write_npz(second, dict(reversed(list(arrays.items()))))
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with np.load(first, allow_pickle=False) as loaded:
                np.testing.assert_array_equal(loaded["tokens"], arrays["tokens"])


if __name__ == "__main__":
    unittest.main()
