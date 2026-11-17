"""When a session expires."""


def expires_at(now, ttl_minutes):
    """The expiry time in epoch seconds: ``now`` (epoch seconds) plus
    ``ttl_minutes`` minutes."""
    return now + ttl_minutes * 60
