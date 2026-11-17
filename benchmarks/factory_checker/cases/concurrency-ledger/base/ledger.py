"""A running balance shared by worker threads."""
import threading


class Ledger:
    def __init__(self):
        self._lock = threading.Lock()
        self._balance = 0

    def _read(self):
        return self._balance

    def _write(self, value):
        self._balance = value

    def add(self, amount):
        """Add ``amount``; safe to call from several threads at once."""
        with self._lock:
            new = self._read() + amount
            self._write(new)
        return new

    @property
    def balance(self):
        return self._balance
