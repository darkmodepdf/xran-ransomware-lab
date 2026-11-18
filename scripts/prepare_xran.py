"""Prepare the pinned XRan feature cohort and independently frozen API split."""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from raneval.xran_data import prepare_release, sha256_file


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "data/raw/xran-original/manifest.json")
    parser.add_argument("--output", type=Path, default=ROOT / "data/processed/xran-original")
    parser.add_argument("--seed", type=int, default=20261117)
    parser.add_argument("--check-reproducibility", action="store_true")
    args = parser.parse_args()
    manifests = prepare_release(args.manifest, args.output, args.seed)
    if args.check_reproducibility:
        expected = {str(path.relative_to(args.output)).replace("\\", "/"): sha256_file(path)
                    for path in args.output.rglob("*")
                    if path.is_file() and path.name not in ("reproducibility.json", "build-receipt.md")}
        with tempfile.TemporaryDirectory(prefix="xran-prepare-repeat-") as temporary:
            repeat = Path(temporary)
            prepare_release(args.manifest, repeat, args.seed)
            observed = {str(path.relative_to(repeat)).replace("\\", "/"): sha256_file(path)
                        for path in repeat.rglob("*") if path.is_file()}
            if expected != observed:
                raise RuntimeError("Prepared artifacts are not byte-reproducible")
        receipt = {"schema": "xran-preparation-reproducibility-v1", "runs": 2,
                   "all_artifacts_byte_identical": True, "artifact_sha256": expected,
                   "npz_policy": "sorted entries, fixed 1980 timestamp, no pickle; array byte hashes in manifest"}
        (args.output / "reproducibility.json").write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({name: {"groups": manifest["group_count"],
                             "role_class_counts": manifest["role_class_counts"],
                             "vocabulary_sha256": manifest["artifacts"]["vocabulary.json"]["sha256"],
                             "identity_sha256": manifest["identity_sha256"]}
                      for name, manifest in manifests.items()}, indent=2))


if __name__ == "__main__":
    main()
