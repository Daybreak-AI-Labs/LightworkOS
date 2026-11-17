"""Compute a value once per key."""
import threading


class OnceCache:
    """``get(key, factory)`` runs ``factory`` at most once per key, even when
    several threads ask for the same key at the same time."""

    def __init__(self):
        self._lock = threading.Lock()
        self._values = {}

    def get(self, key, factory):
        with self._lock:
            if key not in self._values:
                self._values[key] = factory()
            return self._values[key]
