# Environment Threat Hunter standalone demo

This defensive standalone app ingests generic JSON, syslog, CloudTrail,
Kubernetes audit exports, and a safe deterministic subset of user-supplied
Sigma rules. Raw telemetry
is processed in memory and discarded; only minimized findings, investigations,
and response proposals enter the unsigned local JSON store.

| Runtime situation | Analysis backend | Record and governance authority |
| --- | --- | --- |
| `ENV_HUNTER_STANDALONE=1` | Vendored ingestion and detector; no `maverick` import | Unsigned local derived-record store |
| Auto mode, core absent | Vendored ingestion and detector | Unsigned local derived-record store |
| Auto mode, core importable | `maverick.env_hunt` analysis adapters | Unsigned local store; **not** integrated governance |

The standalone requirements intentionally do not install `maverick`. Finding
the core library changes analysis only; managed connectors, audit, governed
approval, and response execution remain in `/security/soc`.

```bash
python -m pip install -r requirements.txt
bash run_standalone.sh                 # http://127.0.0.1:8893
```

Set `ENV_HUNTER_STANDALONE=1` to force isolation, `ENV_HUNTER_STORE` to select
the derived-record store, and `ENV_HUNTER_PORT` to select the port. This reduced
app is always proposal-only: it deliberately has no response-delivery endpoint,
webhook relay, or local approval assertion. Governed execution requires an exact
stored-proposal and approval boundary in Lightwork's `/security/soc` workspace.
Mutations require `application/json` and an exact non-negative
`expected_revision`. The app admits only loopback Hosts and same-loopback-origin
browser writes, streams bodies through a 512 KiB cap, and serializes local CAS
commits across processes.

If the Lightwork detector library is importable, this demo can reuse that
deterministic engine. Its HTTP input and local JSON store remain unsigned and
outside the integrated platform trust boundary; the capability page says so.
Native CloudTrail, syslog, and Kubernetes exports are normalized before that
optional detector runs, and its audit callback is always inert in this web app.

See the [integrated Security & GRC capability and authority matrix](../../docs/SECURITY_GRC.md)
for connector-extension, approval, regulatory-clock, and evidence boundaries.
