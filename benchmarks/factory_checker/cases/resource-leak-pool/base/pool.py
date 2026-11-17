"""A tiny connection pool."""


class Pool:
    def __init__(self, size):
        self._free = [object() for _ in range(size)]

    @property
    def available(self):
        return len(self._free)

    def acquire(self):
        if not self._free:
            raise RuntimeError("pool exhausted")
        return self._free.pop()

    def release(self, conn):
        self._free.append(conn)


def with_conn(pool, fn):
    """``fn(conn)`` with a pooled connection, always given back."""
    conn = pool.acquire()
    try:
        return fn(conn)
    finally:
        pool.release(conn)
