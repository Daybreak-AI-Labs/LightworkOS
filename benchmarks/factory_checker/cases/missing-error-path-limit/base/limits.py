"""The request limit, from the environment."""

DEFAULT_LIMIT = 100


def read_limit(env):
    """LIMIT from ``env`` as a number, or DEFAULT_LIMIT when it is not set."""
    raw = env.get("LIMIT")
    if raw is None:
        return DEFAULT_LIMIT
    return int(raw)
