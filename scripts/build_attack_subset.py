"""Build app/data/attack_subset.json from the MITRE ATT&CK Enterprise STIX bundle (spec 6.5).

Usage: python scripts/build_attack_subset.py [--file BUNDLE.json]

Without --file the pinned release is downloaded from MITRE's GitHub repository. Either way the
bundle's sha256 must equal the pinned one, or nothing is written. The raw bundle is not committed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from collections.abc import Sequence
from pathlib import Path
from typing import Any

VERSION = "20.0"
SHA256 = "81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352"
URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    f"enterprise-attack/enterprise-attack-{VERSION}.json"
)
OUT = Path(__file__).resolve().parent.parent / "app" / "data" / "attack_subset.json"
MAX_BYTES = 200_000_000


def _download() -> bytes:
    with urllib.request.urlopen(URL, timeout=60) as resp:  # noqa: S310 (fixed https URL)
        data: bytes = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("bundle is larger than expected")
    return data


def build(raw: bytes, expected_sha256: str = SHA256) -> dict[str, Any]:
    """Check the hash, then keep id, name, tactics and url of every live technique."""
    digest = hashlib.sha256(raw).hexdigest()
    if digest != expected_sha256:
        raise ValueError(f"sha256 mismatch: got {digest}, expected {expected_sha256}")
    techniques: dict[str, dict[str, Any]] = {}
    for obj in json.loads(raw)["objects"]:
        if (
            obj.get("type") != "attack-pattern"
            or obj.get("revoked")
            or obj.get("x_mitre_deprecated")
        ):
            continue
        ref = next(
            (
                r
                for r in obj.get("external_references", [])
                if r.get("source_name") == "mitre-attack"
            ),
            None,
        )
        if ref is None or not ref.get("external_id"):
            continue
        tactics = sorted(
            p["phase_name"].replace("-", " ").title().replace(" And ", " and ")
            for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        )
        techniques[ref["external_id"]] = {
            "name": obj["name"],
            "tactics": tactics,
            "url": ref.get("url", ""),
        }
    if not techniques:
        raise ValueError("no techniques found")
    return {
        "version": VERSION,
        "sha256": digest,
        "techniques": dict(sorted(techniques.items())),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    parser.add_argument("--file", type=Path, default=None, help="use a bundle already on disk")
    args = parser.parse_args(argv)
    try:
        raw = args.file.read_bytes() if args.file else _download()
        subset = build(raw)
    except (OSError, ValueError, KeyError) as exc:
        print(f"cannot build the ATT&CK subset: {exc}", file=sys.stderr)
        return 1
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(subset, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {len(subset['techniques'])} techniques (ATT&CK {VERSION}) to {OUT}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
