"""Settings > All settings with every group's settings in it.

The page arrives with the list of groups and loads a group's settings when it
is opened (``/settings/all?group=<slug>`` renders one group). ``every_group``
returns each group's page joined, for a test that reads every setting's row.
"""

from __future__ import annotations


def save_catalog(client, path, *, json, **kwargs):
    """Read the same authenticated catalog revision before an ordinary save.

    Explicit revisions are preserved so conflict/invalid-review tests still
    exercise their selected value. A denied read gets a syntactically valid
    sentinel; the subsequent write must still enforce its own authorization.
    """
    body = dict(json)
    if "expected_revision" not in body:
        read_args = {key: value for key, value in kwargs.items() if key in {"headers", "cookies", "auth"}}
        review = client.get(path, params={"q": "__fixture_revision_snapshot__"}, **read_args)
        assert review.status_code in {200, 401, 403}, review.text
        body["expected_revision"] = review.json()["revision"] if review.status_code == 200 else "0" * 64
    return client.post(path, json=body, **kwargs)


def every_group(client, **kwargs) -> str:
    from maverick_dashboard import settings_catalog
    from maverick_dashboard.settings_all_page import _slug

    pages = []
    for name in settings_catalog.GROUPS:
        response = client.get("/settings/all", params={"group": _slug(name)}, **kwargs)
        assert response.status_code == 200, (name, response.status_code)
        pages.append(response.text)
    return "\n".join(pages)
