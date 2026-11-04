"""Tamper-evident screenshot seals."""
from __future__ import annotations

import json

import pytest
from maverick.screenshot_seal import (
    SealKeyMissing,
    _anchor_path,
    seal,
    verify_file,
    verify_ledger,
)

KEY = "seal-key"


def _capture(tmp_path, name="shot1.png", data=b"PNGDATA"):
    p = tmp_path / name
    p.write_bytes(data)
    return p


def test_seal_and_verify_valid(tmp_path):
    p = _capture(tmp_path)
    entry = seal(p, key=KEY)
    assert entry.prev == ""  # first in chain
    assert verify_file(p, key=KEY) == "VALID"


def test_modified_file_is_tampered(tmp_path):
    p = _capture(tmp_path)
    seal(p, key=KEY)
    p.write_bytes(b"DIFFERENT")
    assert verify_file(p, key=KEY) == "TAMPERED"


def test_unsealed_and_wrong_key(tmp_path):
    p = _capture(tmp_path)
    assert verify_file(p, key=KEY) == "UNSEALED"
    seal(p, key=KEY)
    assert verify_file(p, key="other-key") == "TAMPERED"


def test_chain_links_and_break_detection(tmp_path):
    p1 = _capture(tmp_path, "a.png", b"A")
    p2 = _capture(tmp_path, "b.png", b"B")
    seal(p1, key=KEY)
    e2 = seal(p2, key=KEY)
    assert e2.prev != ""
    report = verify_ledger(tmp_path, key=KEY)
    assert report["ok"] and report["entries"] == 2
    # Delete the first ledger line: chain breaks at index 0.
    ledger = tmp_path / ".seals.jsonl"
    lines = ledger.read_text().splitlines()
    ledger.write_text("\n".join(lines[1:]) + "\n")
    broken = verify_ledger(tmp_path, key=KEY)
    assert not broken["ok"] and broken["broken_at"] == 0


def test_ledger_detects_missing_and_modified(tmp_path):
    p1 = _capture(tmp_path, "a.png", b"A")
    p2 = _capture(tmp_path, "b.png", b"B")
    seal(p1, key=KEY)
    seal(p2, key=KEY)
    p1.unlink()
    p2.write_bytes(b"EDITED")
    report = verify_ledger(tmp_path, key=KEY)
    assert report["missing_files"] == ["a.png"]
    assert report["modified_files"] == ["b.png"]
    assert not report["ok"]


def test_recapture_supersedes(tmp_path):
    p = _capture(tmp_path, "a.png", b"V1")
    seal(p, key=KEY)
    p.write_bytes(b"V2")
    seal(p, key=KEY)  # legitimate re-capture
    report = verify_ledger(tmp_path, key=KEY)
    assert report["ok"]  # only the latest seal pins current bytes
    assert verify_file(p, key=KEY) == "VALID"


def test_ledger_tail_truncation_is_tampered(tmp_path):
    p = _capture(tmp_path, "a.png", b"V1")
    seal(p, key=KEY)
    ledger = tmp_path / ".seals.jsonl"
    first_line = ledger.read_text().splitlines()[0]
    p.write_bytes(b"V2")
    seal(p, key=KEY)

    # Simulate rollback: remove the newest signed seal and restore old bytes.
    ledger.write_text(first_line + "\n")
    p.write_bytes(b"V1")

    report = verify_ledger(tmp_path, key=KEY)
    assert not report["ok"]
    assert report["anchor"] == "mismatch"
    assert verify_file(p, key=KEY) == "TAMPERED"


@pytest.mark.parametrize("anchor_json", ["[]", "1"])
def test_malformed_anchor_json_is_tampered_not_crash(tmp_path, anchor_json):
    p = _capture(tmp_path)
    seal(p, key=KEY)
    anchor = _anchor_path(tmp_path)
    anchor.write_text(anchor_json)

    report = verify_ledger(tmp_path, key=KEY)
    assert not report["ok"]
    assert report["anchor"] == "invalid"
    assert verify_file(p, key=KEY) == "TAMPERED"


def test_missing_key_refuses(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_SCREENSHOT_KEY", raising=False)
    import maverick.config as config_mod
    monkeypatch.setattr(config_mod, "load_config", dict)
    p = _capture(tmp_path)
    with pytest.raises(SealKeyMissing):
        seal(p)


def test_entry_tamper_flagged(tmp_path):
    p = _capture(tmp_path)
    seal(p, key=KEY)
    ledger = tmp_path / ".seals.jsonl"
    entry = json.loads(ledger.read_text())
    entry["sha256"] = "0" * 64  # forge the hash without re-signing
    ledger.write_text(json.dumps(entry, sort_keys=True) + "\n")
    assert verify_file(p, key=KEY) == "TAMPERED"


def test_computer_screenshot_seals_when_key_set(tmp_path, monkeypatch):
    """The computer tool's screenshot path persists + seals when a key is set."""
    import base64 as _b64

    import maverick.paths as paths_mod
    import maverick.tools.computer as comp

    monkeypatch.setenv("MAVERICK_SCREENSHOT_KEY", KEY)
    monkeypatch.setattr(paths_mod, "data_dir",
                        lambda *parts, tenant="__active__": tmp_path.joinpath(*parts))
    png_b64 = _b64.b64encode(b"FAKEPNG").decode()
    comp._maybe_seal_capture(png_b64)
    captures = list((tmp_path / "captures").glob("*.png"))
    assert len(captures) == 1
    assert verify_file(captures[0], key=KEY) == "VALID"


def test_computer_screenshot_no_key_no_capture(tmp_path, monkeypatch):
    import base64 as _b64

    import maverick.config as config_mod
    import maverick.paths as paths_mod
    import maverick.tools.computer as comp

    monkeypatch.delenv("MAVERICK_SCREENSHOT_KEY", raising=False)
    monkeypatch.setattr(config_mod, "load_config", dict)
    monkeypatch.setattr(paths_mod, "data_dir",
                        lambda *parts, tenant="__active__": tmp_path.joinpath(*parts))
    comp._maybe_seal_capture(_b64.b64encode(b"X").decode())
    assert not (tmp_path / "captures").exists()
