"""Call a flaky function a few times."""


def retry(fn, attempts=3):
    """Call ``fn`` until it succeeds, at most ``attempts`` times; raise the
    last error when every attempt failed."""
    error = None
    for _ in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 -- retried, then re-raised
            error = exc
    raise error
