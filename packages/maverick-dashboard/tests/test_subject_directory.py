"""Login-time OIDC subject directory: bridges IdP identifiers to the session
``sub`` so SCIM deprovision can revoke a pairwise-``sub`` session (Entra)."""
from __future__ import annotations

import json

import pytest
from maverick_dashboard import subject_directory as sd


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))


def test_record_then_lookup_by_each_identifier():
    sd.record_login("pairwise-sub-xyz", ["alice@x.com", "alice", "aad-oid-1"])
    assert sd.subs_for(["alice@x.com"]) == {"pairwise-sub-xyz"}
    assert sd.subs_for(["aad-oid-1"]) == {"pairwise-sub-xyz"}
    assert sd.subs_for(["alice"]) == {"pairwise-sub-xyz"}
    assert sd.subs_for(["unknown@x.com"]) == set()


def test_lookup_is_case_and_space_insensitive():
    sd.record_login("s1", ["Alice@X.com"])
    assert sd.subs_for(["  alice@x.com "]) == {"s1"}


def test_blank_sub_or_identifiers_are_noops():
    sd.record_login("", ["a@x.com"])
    sd.record_login("s", ["", "   ", None])
    assert sd.subs_for(["a@x.com"]) == set()


def test_raw_identifiers_never_hit_disk():
    # Privacy: lookup keys are hashed; the raw email must not appear in the file.
    sd.record_login("s1", ["secret.person@example.com"])
    raw = sd._path().read_text(encoding="utf-8")
    assert "secret.person@example.com" not in raw
    assert "example.com" not in raw
    # The opaque sub (the revocation key, not PII) is stored.
    assert "s1" in raw


def test_corrupt_directory_fails_closed_and_is_not_overwritten():
    sd._path().parent.mkdir(parents=True, exist_ok=True)
    damaged = "{ not json"
    sd._path().write_text(damaged, encoding="utf-8")
    # Authorization/deprovision reads must not interpret damaged lifecycle
    # state as empty. Login recording remains best-effort but cannot erase it.
    with pytest.raises(sd.SubjectDirectoryError, match="corrupt"):
        sd.subs_for(["a@x.com"])
    sd.record_login("s1", ["a@x.com"])
    assert sd._path().read_text(encoding="utf-8") == damaged


def test_lru_prune_keeps_newest(monkeypatch):
    monkeypatch.setattr(sd, "_MAX_ENTRIES", 3)
    for i in range(5):
        sd.record_login(f"sub{i}", [f"user{i}@x.com"], at=float(i))
    data = json.loads(sd._path().read_text(encoding="utf-8"))
    assert len(data) == 3
    # The three newest survive; the two oldest are pruned.
    assert sd.subs_for(["user4@x.com"]) == {"sub4"}
    assert sd.subs_for(["user0@x.com"]) == set()


def test_forget_drops_entries():
    sd.record_login("s1", ["a@x.com", "a"])
    sd.forget(["a@x.com", "a"])
    assert sd.subs_for(["a@x.com"]) == set()


def test_relogin_updates_sub_last_wins():
    sd.record_login("old-sub", ["alice@x.com"], at=1.0)
    sd.record_login("new-sub", ["alice@x.com"], at=2.0)
    assert sd.subs_for(["alice@x.com"]) == {"new-sub"}


def test_retirement_covers_direct_and_pairwise_subject_and_can_be_reinstated():
    sd.record_login("pairwise-sub", ["immutable-oid"])
    sd.retire(["immutable-oid"], at=7.0)

    assert sd.is_retired("immutable-oid") is True
    assert sd.is_retired("pairwise-sub") is True
    raw = sd._retired_path().read_text(encoding="utf-8")
    assert "immutable-oid" not in raw
    assert "pairwise-sub" not in raw

    sd.reinstate(["immutable-oid"])
    assert sd.is_retired("immutable-oid") is False
    assert sd.is_retired("pairwise-sub") is False


def test_new_pairwise_subject_inherits_retired_identifier_durably():
    sd.retire(["immutable-oid"], at=7.0)
    sd.record_login("new-pairwise-sub", ["immutable-oid"], at=8.0)

    assert sd.is_retired("new-pairwise-sub") is True
    # Even if the lookup binding is later pruned, recording permanently copied
    # the retirement decision to the opaque subject itself.
    sd.forget(["immutable-oid"])
    assert sd.is_retired("new-pairwise-sub") is True


def test_corrupt_retirement_ledger_fails_closed_and_is_not_overwritten():
    damaged = '{"subjects":{"bad":NaN}}'
    sd._retired_path().write_text(damaged, encoding="utf-8")

    with pytest.raises(sd.SubjectDirectoryError, match="corrupt"):
        sd.is_retired("someone")
    with pytest.raises(sd.SubjectDirectoryError):
        sd.retire(["someone"])
    assert sd._retired_path().read_text(encoding="utf-8") == damaged
