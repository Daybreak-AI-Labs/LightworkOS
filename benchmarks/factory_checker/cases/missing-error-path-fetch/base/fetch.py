"""Fetch a JSON document through an injected getter."""


class FetchError(Exception):
    """The server did not answer with 200."""


def fetch_json(get, url):
    """``get(url)`` returns (status, body). The body on 200; FetchError otherwise."""
    status, body = get(url)
    if status != 200:
        raise FetchError(f"{url} answered {status}")
    return body
