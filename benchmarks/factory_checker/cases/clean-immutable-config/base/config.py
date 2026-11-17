"""Settings shared between threads."""
import threading


class Config:
    def __init__(self, **values):
        self._lock = threading.Lock()
        self._values = dict(values)

    def get(self, key, default=None):
        with self._lock:
            return self._values.get(key, default)

    def set(self, key, value):
        with self._lock:
            self._values[key] = value
