# Named OAuth refresh ownership

Named OAuth connections retain one reviewed generation across access-token renewal. A refresh owns a per-connection cross-process lock, persists a random pending lease in the tenant-sealed credential record under the short shared store lock, then releases the shared lock before contacting the provider. Independent connections, grants, removals and app-registration changes can proceed while that request is running.

Before publishing returned credentials, renewal reloads current state under the shared lock and checks enabled authority, the caller's grant, the frozen credential/authority record and pending lease, and the exact application registration. A concurrent readiness-test receipt is preserved. A removed, replaced, reauthorized or revoked connection is never revived by a late provider response. Successful renewal preserves its reviewed revision and retires its lease.

The lease deliberately has no automatic expiry that permits replay. A process death releases the operating-system lock but leaves the sealed pending state. If the provider may have consumed a rotating refresh token, Lightwork requires reconnection. It does not resend that old token or claim that a lost response can safely be recovered. Bounded provider requests, origin/scope/account/site validation and secret-safe public status still apply.

Limits: behavior against a live provider and production latency are not qualified.
