"""The protected comparison token the Channels page gives each save.

``/channels/save`` and ``/channels/clear`` accept a change only with the
sealed review the page rendered for this account, workspace and settings
revision (``app._require_channel_review``). Tests read it from the page, as a
browser submits it.
"""
from __future__ import annotations

import html
import re


def channel_review_token(client, **request) -> str:
    page = client.get("/channels", **request)
    assert page.status_code == 200, page.text[:300]
    found = re.search(r'name="review_token" value="([^"]+)"', page.text)
    assert found, "The Channels page carries no protected review token"
    return html.unescape(found.group(1))
