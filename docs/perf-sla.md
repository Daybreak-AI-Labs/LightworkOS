# Lightwork performance SLA (self-hosted)

These are **engineering performance gates**, checked by
`python -m maverick.perf_sla --ci` and the reliability harnesses below.
They are not a customer deployment's measured service level or a release
certification. Record the intended artifact, hardware, workload and results
before using them in release acceptance or a customer commitment.

The thresholds are deliberately conservative (they must hold on a cold
2-vCPU CI runner, not a tuned workstation). On typical developer hardware the
measured numbers are far better.

| # | Property | Threshold | Measured by |
|---|----------|-----------|-------------|
| 1 | Tool-dispatch overhead (registry lookup + schema-validated dispatch of a no-op tool) | < 5 ms p95 | `perf_sla.check_dispatch_overhead` |
| 2 | Compaction pass over a 200-message history | < 250 ms | `perf_sla.check_compaction_latency` |
| 3 | World-model hot-path write (goal event append, WAL) | < 25 ms p95 | `perf_sla.check_world_write` |
| 4 | World-model hot-path read (goal + recent events) | < 25 ms p95 | `perf_sla.check_world_read` |
| 5 | Concurrent WAL writers (16) | 0 lock errors | reliability cert (`wal_contention`) |
| 6 | Transient tool faults (20%) absorbed by the retry layer | ≤ 5% surfaced | chaos game-day |
| 7 | Crash recovery in plugin hosts | every crash followed by a later success | plugin reliability drill |

## What this is not

- Not an uptime/latency promise for *model providers* — their latency and
  availability are theirs.
- Not a benchmark of agent *quality* (see `benchmarks/` and the reproducible
  benchmark harness for that).

## Reproducing

```bash
python -m maverick.perf_sla            # report
python -m maverick.perf_sla --ci      # exit non-zero on any threshold breach
python -m maverick.reliability_cert    # rows 5-7, with a signed certificate
```

Thresholds live in `maverick/perf_sla.py` (`THRESHOLDS`); changing one is a
reviewed act with the same weight as changing the SLA itself.
