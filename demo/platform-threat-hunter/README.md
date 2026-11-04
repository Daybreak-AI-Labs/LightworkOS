# Platform Threat Hunter standalone demo

This reduced defensive app applies deterministic MITRE ATT&CK-tagged rules to
ephemeral platform-event JSON. It persists only minimized derived findings and
investigations; it does not persist raw events and makes no tamper-evidence claim.
Lightwork adds signed-chain input, continuous monitoring, governed containment,
fleet baselines, and the `/security/threats` workspace.

| Runtime situation | Analysis backend | Record and governance authority |
| --- | --- | --- |
| `PLATFORM_HUNTER_STANDALONE=1` | Vendored detector; no `maverick` import | Unsigned local derived-record store |
| Auto mode, core absent | Vendored detector | Unsigned local derived-record store |
| Auto mode, core importable | `maverick.platform_hunt` analysis adapter | Unsigned local store; **not** integrated governance |

The standalone requirements intentionally do not install `maverick`. Finding
the core detector changes only analysis; signed-chain input, monitoring, audit,
and response authority remain in `/security/threats`.

If the Lightwork detector library is importable, this demo can reuse that
deterministic engine. Its HTTP input and local JSON store remain unsigned and
outside the integrated platform trust boundary; the capability page says so.

```bash
python -m pip install -r requirements.txt
bash run_standalone.sh                 # http://127.0.0.1:8892
```

Configuration: `PLATFORM_HUNTER_STANDALONE=1` forces isolation,
`PLATFORM_HUNTER_STORE` selects the derived-record JSON file, and
`PLATFORM_HUNTER_PORT` selects the port.
Mutations require `application/json` and an exact non-negative
`expected_revision`. The app admits only loopback Hosts and same-loopback-origin
browser writes, streams bodies through a 512 KiB cap, and serializes local CAS
commits across processes. Reusing an installed detector never writes the
Lightwork audit chain; submitted standalone input remains outside that trust
boundary.

See the [integrated Security & GRC capability and authority matrix](../../docs/SECURITY_GRC.md)
for the signed-input, governed-approval, and standalone product boundaries.
