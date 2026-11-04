"""scim_groups.active_check: the same answer as active_for_principal (the
sign-in check) for every principal, reading and indexing the stores once."""
from __future__ import annotations

import random

import pytest
from maverick_dashboard import scim, scim_groups, subject_directory


def _stores(rng: random.Random):
    subs = [f"sub-{index}" for index in range(12)]
    users, directory, retired = {}, {}, {}
    for index in range(10):
        uid = f"u{index}"
        record = {"id": rng.choice([uid, subs[index]]), "active": rng.random() < 0.6}
        if rng.random() < 0.7:
            record["externalId"] = rng.choice([f"alice{index}@corp.com", subs[rng.randrange(12)], ""])
        users[uid] = record
    for identifier in [f"alice{index}@corp.com" for index in range(10)] + [f"u{index}" for index in range(10)]:
        if rng.random() < 0.5:
            directory[subject_directory._key(identifier)] = {"sub": rng.choice(subs), "ts": 1.0}
    for key in rng.sample(sorted(directory), k=min(3, len(directory))):
        retired[key] = 1.0                              # an identifier tombstone
    for sub in rng.sample(subs, k=2):
        retired[subject_directory._subject_key(sub)] = 1.0   # a retired subject
    return users, directory, retired


@pytest.mark.parametrize("seed", range(40))
def test_active_check_gives_the_sign_in_answer_for_every_principal(monkeypatch, seed):
    rng = random.Random(seed)
    users, directory, retired = _stores(rng)
    monkeypatch.setattr(scim, "_load", lambda: dict(users))
    monkeypatch.setattr(subject_directory, "_load", lambda: dict(directory))
    monkeypatch.setattr(subject_directory, "_load_retired", lambda: dict(retired))
    principals = ([f"user:sub-{index}" for index in range(14)] + [f"user:u{index}" for index in range(10)]
                  + [f"user:alice{index}@corp.com" for index in range(10)]
                  + ["user:", "", "agent:helper", " user:sub-1 ", "sub-2"])
    check = scim_groups.active_check()
    assert {p: check(p) for p in principals} == {p: scim_groups.active_for_principal(p) for p in principals}


def test_a_corrupt_store_raises_when_the_check_is_built(monkeypatch):
    def corrupt():
        raise scim.ScimStoreError("corrupt")

    monkeypatch.setattr(scim, "_load", corrupt)
    with pytest.raises(scim.ScimStoreError):
        scim_groups.active_check()
