from __future__ import annotations

import hashlib
import io
import json
import sys
import urllib.request
from pathlib import Path

import pytest

from app import attack

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import build_attack_subset as bas


def pattern(ext_id: str, name: str, *phases: str, **flags: bool) -> dict[str, object]:
    return {
        "type": "attack-pattern",
        "name": name,
        "external_references": [
            {"source_name": "other", "external_id": "X1"},
            {"source_name": "mitre-attack", "external_id": ext_id, "url": f"https://x/{ext_id}"},
        ],
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": p} for p in phases],
        **flags,
    }


def bundle(*objects: dict[str, object]) -> bytes:
    return json.dumps({"objects": list(objects)}).encode()


def test_build_keeps_live_techniques_only() -> None:
    raw = bundle(
        pattern("T1", "Live", "command-and-control", "credential-access"),
        pattern("T1.001", "Sub", "execution"),
        pattern("T2", "Gone", "execution", revoked=True),
        pattern("T3", "Old", "execution", x_mitre_deprecated=True),
        {"type": "malware", "name": "not a technique"},
        {"type": "attack-pattern", "name": "no ref", "external_references": []},
    )
    out = bas.build(raw, hashlib.sha256(raw).hexdigest())
    assert list(out["techniques"]) == ["T1", "T1.001"]
    assert out["techniques"]["T1"]["tactics"] == ["Command and Control", "Credential Access"]
    assert out["techniques"]["T1"]["url"] == "https://x/T1"


def test_build_refuses_a_wrong_hash() -> None:
    with pytest.raises(ValueError, match="sha256 mismatch"):
        bas.build(bundle(pattern("T1", "A", "execution")))


def test_build_refuses_an_empty_result() -> None:
    raw = bundle({"type": "malware"})
    with pytest.raises(ValueError, match="no techniques"):
        bas.build(raw, hashlib.sha256(raw).hexdigest())


def test_main_writes_and_reports_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    raw = bundle(pattern("T1", "A", "execution"))
    monkeypatch.setattr(bas, "SHA256", hashlib.sha256(raw).hexdigest())
    monkeypatch.setattr(bas, "OUT", tmp_path / "out" / "subset.json")
    src = tmp_path / "b.json"
    src.write_bytes(raw)
    original = bas.build  # build()'s default hash was bound at import, so pass the patched one
    monkeypatch.setattr(bas, "build", lambda r: original(r, bas.SHA256))
    assert bas.main(["--file", str(src)]) == 0
    assert (
        json.loads((tmp_path / "out" / "subset.json").read_text("utf-8"))["version"] == bas.VERSION
    )
    assert "wrote 1 techniques" in capsys.readouterr().out
    assert bas.main(["--file", str(tmp_path / "missing.json")]) == 1
    assert "cannot build" in capsys.readouterr().err


def test_download_checks_size(monkeypatch: pytest.MonkeyPatch) -> None:
    class Resp(io.BytesIO):
        def __enter__(self) -> Resp:
            return self

        def __exit__(self, *a: object) -> None:
            self.close()

    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: Resp(b"abc"))
    assert bas._download() == b"abc"
    monkeypatch.setattr(bas, "MAX_BYTES", 2)
    with pytest.raises(ValueError, match="larger"):
        bas._download()


def test_shipped_subset_matches_the_pin() -> None:
    data = json.loads(attack.SUBSET.read_text("utf-8"))
    assert (data["version"], data["sha256"]) == (bas.VERSION, bas.SHA256)
    assert attack.version() == bas.VERSION
    assert len(data["techniques"]) > 500


def test_describe_known_and_unknown() -> None:
    assert attack.describe("T1110")["name"] == "Brute Force"
    assert attack.describe("T1110.001")["tactics"] == ["Credential Access"]
    assert attack.describe("T9999") == {"id": "T9999", "name": "Unknown", "tactics": [], "url": ""}
