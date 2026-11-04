"""HTTP-plane load harness: prove the dashboard API holds under concurrency.

``control_data_plane_soak`` proves the dispatch substrate; this drives the
**HTTP plane** — the real FastAPI app, its middleware stack (CSRF, metrics),
and the governed-record estate behind it — with a pool of concurrent clients,
and asserts the load-bearing guarantees:

* **No 5xx** — every response is an intended status. Contention surfaces as
  409 (the governed-record CAS) and never as an error page.
* **Admission holds under contention** — N clients racing to register the
  SAME vendor name end with exactly one record ("the same name is one
  record, never a duplicate" is a promise about races, not just retries).
* **The world survives** — SQLite ``PRAGMA integrity_check`` is clean after
  the run.
* **The meter counts** — ``lightwork_http_requests_total`` on ``/metrics``
  accounts for at least every request the harness issued (a thread-unsafe
  counter undercounts under exactly this load).

Latency percentiles are recorded but never asserted: timings are
host-dependent, and a wall-clock gate in CI is a flake generator. The LLM
boundary is never reached — every endpoint in the mix is a read or an
estate write — so the run is offline and needs no provider key.

Two transports, same assertions: ``inprocess`` drives the ASGI app
directly (fast, hermetic), ``http`` serves it under uvicorn on a loopback
socket so the run crosses a real HTTP parser, real keep-alive, and the
server's own concurrency handling. The guarantees hold on both because
they are properties of the app, not of the transport — and a claim that
only survives without a socket is not a claim about production.

``run_load`` drives an environment the CALLER has already pinned (isolated
``MAVERICK_HOME``/``MAVERICK_CONFIG`` with ``[vendor_management] enable``,
``world_model.DEFAULT_DB`` at a scratch path, dashboard caches cleared) —
tests pin it with ``monkeypatch`` exactly like the estate-API tests. The CLI
entry point pins a throwaway environment itself:
``python -m maverick_dashboard.load_harness --ci``.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

_DEFAULT_WORKERS = 8
_DEFAULT_REQUESTS = 24          # iterations per worker; each is 5 requests
_CONTENDED_VENDOR = "Contended Vendor GmbH"


def _percentile(sorted_values: list[float], q: float) -> float:
    if not sorted_values:
        return 0.0
    idx = min(len(sorted_values) - 1, int(round(q * (len(sorted_values) - 1))))
    return sorted_values[idx]


def _metric_total(metrics_text: str, name: str) -> float:
    total = 0.0
    for line in metrics_text.splitlines():
        if line.startswith(name) and " " in line:
            try:
                total += float(line.rsplit(" ", 1)[1])
            except ValueError:
                continue
    return total


class _LoopbackServer:
    """Serve the app over a REAL loopback socket for the duration of a run.

    The in-process transport exercises the middleware stack but never a
    socket: no HTTP parsing, no keep-alive, no server-side concurrency
    limits. This runs the same app under uvicorn on 127.0.0.1 so the
    harness measures the stack an operator actually deploys. Loopback
    only -- the harness never binds a routable interface.
    """

    def __init__(self, app, *, startup_timeout: float = 30.0) -> None:
        self._app = app
        self._startup_timeout = startup_timeout
        self._server = None
        self._thread = None
        self.base_url = ""

    def __enter__(self) -> _LoopbackServer:
        import threading

        import uvicorn

        config = uvicorn.Config(
            self._app, host="127.0.0.1", port=0, log_level="warning",
            lifespan="on", access_log=False,
        )
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._server.run, daemon=True)
        self._thread.start()
        deadline = time.time() + self._startup_timeout
        while not self._server.started:
            if time.time() > deadline or not self._thread.is_alive():
                self.__exit__(None, None, None)
                raise RuntimeError("load harness: uvicorn did not start")
            time.sleep(0.02)
        port = self._server.servers[0].sockets[0].getsockname()[1]
        self.base_url = f"http://127.0.0.1:{port}"
        return self

    def __exit__(self, *_exc) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=self._startup_timeout)
        self._server = None
        self._thread = None


def run_load(world_db: Path, *, workers: int = _DEFAULT_WORKERS,
             requests: int = _DEFAULT_REQUESTS,
             transport: str = "inprocess") -> dict:
    """Drive the app with ``workers`` concurrent clients; return evidence.

    ``world_db`` must be the same scratch path the caller pinned as
    ``world_model.DEFAULT_DB`` (asserted, so a mispinned harness fails loudly
    instead of measuring the wrong database).

    ``transport`` is ``"inprocess"`` (ASGI, no socket -- fast, hermetic) or
    ``"http"`` (uvicorn on loopback, so the run crosses a real socket and
    a real HTTP parser). Every guarantee below is asserted identically on
    both, because they are properties of the app, not of the transport.
    """
    from maverick import world_model

    world_db = Path(world_db)
    if Path(world_model.DEFAULT_DB) != world_db:
        raise RuntimeError(
            "run_load: world_model.DEFAULT_DB is not pinned to the harness "
            "database -- pin the environment before driving load")

    import contextlib

    from fastapi.testclient import TestClient

    from maverick_dashboard.app import app

    transport = str(transport or "inprocess").strip().lower()
    if transport not in ("inprocess", "http"):
        raise ValueError('transport must be "inprocess" or "http"')

    # One seeded goal so the read side has a real row to serve.
    gid = world_model.WorldModel(world_db).create_goal("load harness", "seed")

    statuses: dict[int, int] = {}
    latencies: list[float] = []
    unexpected: list[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(workers)
    issued = 0

    def _hit(client, method: str, path: str, ok: set[int], **kw) -> None:
        nonlocal issued
        t0 = time.perf_counter()
        response = getattr(client, method)(path, **kw)
        elapsed = time.perf_counter() - t0
        with lock:
            issued += 1
            latencies.append(elapsed)
            statuses[response.status_code] = (
                statuses.get(response.status_code, 0) + 1)
            if response.status_code not in ok:
                unexpected.append(
                    f"{method.upper()} {path} -> {response.status_code}: "
                    f"{response.text[:200]}")

    def _client():
        # The same-origin CSRF check compares Origin against the host the
        # request actually arrived on, so the header has to be the REAL
        # origin. Over a socket that is the loopback port -- the in-process
        # transport never notices, because there the invented host and the
        # invented Origin agree with each other.
        if transport == "http":
            import httpx

            return httpx.Client(
                base_url=base_url, headers={"Origin": base_url}, timeout=30.0)
        # No context manager: the suite-wide pattern drives the app without
        # entering its lifespan, and N concurrent startups are not the test.
        return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})

    def _worker(worker_id: int) -> None:
        client = _client()
        try:
            barrier.wait()
            for i in range(requests):
                _hit(client, "get", "/livez", {200})
                _hit(client, "get", f"/api/v1/goals/{gid}", {200})
                _hit(client, "get", "/api/v1/vendors", {200})
                # Unique name: always admitted. Contended name: exactly one
                # winner across the whole run, losers get the CAS 409.
                name = (_CONTENDED_VENDOR if i % 2 else
                        f"Vendor {worker_id}-{i}")
                _hit(client, "post", "/api/v1/vendors", {201, 409}, json={
                    "name": name, "category": "load", "criticality": "low",
                    "owner": "harness",
                })
                _hit(client, "get", "/metrics", {200})
        finally:
            client.close()

    threads = [threading.Thread(target=_worker, args=(w,), daemon=True)
               for w in range(workers)]
    server = (_LoopbackServer(app) if transport == "http"
              else contextlib.nullcontext())
    with server as running:
        base_url = getattr(running, "base_url", "")
        t_start = time.time()
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        wall = time.time() - t_start

        reader = _client()
        try:
            rows = reader.get("/api/v1/vendors").json()["vendors"]
            contended = [r for r in rows if r["name"] == _CONTENDED_VENDOR]
            metrics_text = reader.get("/metrics").text
        finally:
            reader.close()
    counted = _metric_total(metrics_text, "lightwork_http_requests_total")
    integrity = sqlite3.connect(str(world_db)).execute(
        "PRAGMA integrity_check").fetchone()[0]

    latencies.sort()
    unique_names = workers * ((requests + 1) // 2)
    checks = {
        "no_5xx": not any(code >= 500 for code in statuses),
        "no_unexpected_status": not unexpected,
        "contended_name_is_one_record": len(contended) == 1,
        "unique_names_all_admitted": len(rows) == 1 + unique_names,
        "requests_all_metered": counted >= issued,
        "world_db_integrity_ok": integrity == "ok",
    }
    return {
        "suite": "dashboard-load-v1",
        "ok": all(checks.values()),
        "checks": checks,
        "transport": transport,
        "workers": workers,
        "requests_per_worker": requests,
        "requests_issued": issued,
        "statuses": {str(k): v for k, v in sorted(statuses.items())},
        "unexpected": unexpected[:20],
        "vendor_rows": len(rows),
        "metered_requests": counted,
        "wall_seconds": round(wall, 3),
        # Recorded, never asserted: host-dependent.
        "latency_seconds": {
            "p50": round(_percentile(latencies, 0.50), 4),
            "p95": round(_percentile(latencies, 0.95), 4),
            "p99": round(_percentile(latencies, 0.99), 4),
        },
    }


def _pin_environment(workdir: Path) -> Path:  # pragma: no cover -- CLI shell
    """Point this PROCESS at a throwaway home + world DB (standalone runs).

    Tests never call this: they pin the same things with ``monkeypatch`` so
    the pins are undone; a standalone process just exits.
    """
    import os

    from maverick import config as maverick_config
    from maverick import world_model

    home = workdir / "home"
    home.mkdir(parents=True, exist_ok=True)
    config_path = home / "config.toml"
    config_path.write_text("[vendor_management]\nenable = true\n",
                           encoding="utf-8")
    os.environ["MAVERICK_HOME"] = str(home)
    os.environ["MAVERICK_CONFIG"] = str(config_path)
    # Hermetic without the crypto extra, same boundary as the e2e/soak gates.
    os.environ["MAVERICK_ENCRYPT_AT_REST"] = "0"
    os.environ.pop("MAVERICK_DASHBOARD_TOKEN", None)
    maverick_config.reset_config_cache()
    world_db = workdir / "world.db"
    world_model.DEFAULT_DB = world_db
    return world_db


def main(argv: list[str] | None = None) -> int:  # pragma: no cover -- CLI shell
    import argparse
    import tempfile

    p = argparse.ArgumentParser(
        description="dashboard HTTP-plane load harness")
    p.add_argument("--ci", action="store_true",
                   help="exit non-zero if a guarantee breaks")
    p.add_argument("--workers", type=int, default=_DEFAULT_WORKERS)
    p.add_argument("--requests", type=int, default=_DEFAULT_REQUESTS)
    p.add_argument("--transport", choices=("inprocess", "http"),
                   default="inprocess",
                   help="ASGI in-process, or a real loopback HTTP hop.")
    p.add_argument("--out", help="write the evidence JSON here")
    args = p.parse_args(argv)

    with tempfile.TemporaryDirectory(prefix="lightwork-load-") as tmp:
        world_db = _pin_environment(Path(tmp))
        proof = run_load(world_db, workers=max(1, args.workers),
                         requests=max(1, args.requests),
                         transport=args.transport)
    print(json.dumps(proof, indent=2))
    if args.out:
        Path(args.out).write_text(json.dumps(proof, indent=2) + "\n",
                                  encoding="utf-8")
    if args.ci and not proof["ok"]:
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
