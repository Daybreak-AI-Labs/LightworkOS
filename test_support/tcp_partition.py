"""Owned loopback-only relay for native transport failure tests; never logs bytes."""
from __future__ import annotations

import contextlib
import select
import socket
import threading


class LocalPartitionRelay:
    def __init__(self, target: tuple[str, int]):
        if target[0] not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("transport qualification requires an explicit local target")
        self.target = target
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.listener.settimeout(.1)
        self.address = self.listener.getsockname()
        self._lock = threading.Lock()
        self._peers: dict[socket.socket, socket.socket | None] = {}
        self._upstreams: set[socket.socket] = set()
        self._closed = threading.Event()
        self._blackhole = threading.Event()
        self._blackhole_responses = threading.Event()
        self._worker = threading.Thread(target=self._run, name="owned-local-pg-relay")
        self._worker.start()

    def blackhole(self):
        self._blackhole.set()

    def blackhole_responses(self):
        self._blackhole_responses.set()

    def _forget(self, stream):
        with self._lock:
            peer = self._peers.pop(stream, None)
            self._upstreams.discard(stream)
            if peer is not None:
                self._peers.pop(peer, None)
                self._upstreams.discard(peer)
        for owned in (stream, peer):
            if owned is not None:
                with contextlib.suppress(OSError):
                    owned.shutdown(socket.SHUT_RDWR)
                owned.close()

    def _accept(self):
        stream, _ = self.listener.accept()
        stream.settimeout(.2)
        peer = None
        try:
            if not self._blackhole.is_set():
                peer = socket.create_connection(self.target, timeout=1)
                peer.settimeout(.2)
            with self._lock:
                if self._closed.is_set() or len(self._peers) >= 32:
                    stream.close()
                    if peer is not None:
                        peer.close()
                    return
                self._peers[stream] = peer
                if peer is not None:
                    self._peers[peer] = stream
                    self._upstreams.add(peer)
        except OSError:
            stream.close()
            if peer is not None:
                peer.close()

    def _run(self):
        while not self._closed.is_set():
            with self._lock:
                streams = [self.listener, *self._peers]
            try:
                readable, _, _ = select.select(streams, [], [], .05)
            except (OSError, ValueError):
                continue
            for stream in readable:
                try:
                    if stream is self.listener:
                        self._accept()
                        continue
                    block = stream.recv(64 * 1024)
                    if not block:
                        self._forget(stream)
                        continue
                    with self._lock:
                        peer = self._peers.get(stream)
                        response = stream in self._upstreams
                    if (peer is not None and not self._blackhole.is_set()
                            and not (response and self._blackhole_responses.is_set())):
                        peer.sendall(block)
                except OSError:
                    if stream is not self.listener:
                        self._forget(stream)

    def close(self):
        self._closed.set()
        self.listener.close()
        with self._lock:
            streams = list(self._peers)
        for stream in streams:
            self._forget(stream)
        self._worker.join(timeout=3)
        if self._worker.is_alive():
            raise RuntimeError("owned local relay did not stop")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
