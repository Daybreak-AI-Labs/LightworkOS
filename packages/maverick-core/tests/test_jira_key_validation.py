"""Jira issue-key validation: the key is interpolated into the REST path, so a
model-supplied ``../myself`` / ``DEMO-1?expand=x`` must be refused before any
request (path-traversal / query-injection into another authed endpoint)."""
from __future__ import annotations

import pytest
from maverick.tools import jira as jira_mod


@pytest.mark.parametrize("key", ["PROJ-123", "AB-1", "ABC123-9999", "X_Y-7"])
def test_require_key_accepts_literal_keys(key):
    assert jira_mod._require_key(key) == key


@pytest.mark.parametrize("key", [
    "../myself",                       # path traversal to another endpoint
    "../../rest/api/3/myself",
    "DEMO-1?expand=changelog",         # query-param injection
    "DEMO-1/comment",                  # extra path segment
    "DEMO-1#frag",
    "PROJ-1 OR 1=1",                   # space / smuggled clause
    "proj-123",                        # lowercase (not a real key shape)
    "PROJ-",                           # no number
    "-123",                            # no project
    "",                                # empty
])
def test_require_key_rejects_traversal_and_injection(key):
    with pytest.raises(ValueError):
        jira_mod._require_key(key)


@pytest.mark.parametrize("fn", [
    lambda k: jira_mod._get(k),
    lambda k: jira_mod._comment(k, "body"),
    lambda k: jira_mod._transition(k, "Done"),
])
def test_path_ops_reject_bad_key_before_any_request(fn):
    # The guard fires before _client() (which would import httpx and open a
    # connection), so a hostile key never reaches the network.
    with pytest.raises(ValueError):
        fn("../../../rest/api/3/myself")
