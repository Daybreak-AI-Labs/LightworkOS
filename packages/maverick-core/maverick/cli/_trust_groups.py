"""Trust-plane CLI groups: capability, trust, client, backup.

Registered by importing this module at the end
of the package __init__ so the @main.group decorators fire on package import.
"""
from __future__ import annotations

import click

from . import main, open_world


@main.group("capability")
def capability_group() -> None:
    """Revoke / restore capability grants (kill a grant before its TTL)."""


@capability_group.command("revoke")
@click.argument("principal")
@click.option("--reason", default="", help="Audit reason for the revocation.")
def capability_revoke_cmd(principal: str, reason: str) -> None:
    """Revoke PRINCIPAL now. Its next tool call is denied even mid-run.

    Propagates to running agents (the registry is re-read on change) when
    capability enforcement is on ([capabilities] enforce = true).
    """
    from ..revocation import shared
    rev = shared().revoke(principal, reason=reason)
    click.echo(click.style(f"revoked {principal!r}", fg="yellow")
               + (f" — {rev.reason}" if rev.reason else ""))


@capability_group.command("unrevoke")
@click.argument("principal")
def capability_unrevoke_cmd(principal: str) -> None:
    """Restore an ordinary revocation; containment requires security release."""
    from ..revocation import ProtectedRevocationError, shared
    try:
        restored = shared().unrevoke(principal)
    except ProtectedRevocationError as exc:
        raise click.ClickException(str(exc)) from exc
    if restored:
        click.echo(click.style(f"restored {principal!r}", fg="green"))
    else:
        click.echo(f"{principal!r} was not revoked")


@capability_group.command("revocations")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def capability_revocations_cmd(as_json: bool) -> None:
    """List revoked principals."""
    import json as _json

    from ..revocation import shared
    revs = shared().revoked()
    if as_json:
        click.echo(_json.dumps(
            {p: {"revoked_at": r.revoked_at, "reason": r.reason,
                 "protected": r.protected}
             for p, r in revs.items()}, default=str))
        return
    if not revs:
        click.echo("no revoked principals")
        return
    for p, r in sorted(revs.items()):
        click.echo(f"  {p}  (at {r.revoked_at:.0f})"
                   + ("  [CONTAINED]" if r.protected else "")
                   + (f"  — {r.reason}" if r.reason else ""))


@main.group("trust")
def trust_group() -> None:
    """Administer the Agent Trust registry (which OUTSIDE agents may be talked to).

    The registry governs every external surface (federation, A2A, fleet, channel,
    marketplace, gRPC, MCP). Hand-edited ``[agent_trust] agents`` in config stays
    read-only; these commands manage a per-client overlay (``agent_trust.json``)
    so you can add / rotate / revoke peers and their pinned keys without editing
    TOML. Engaged via enterprise mode or ``[agent_trust] enforce = true``."""


@trust_group.command("status")
def trust_status_cmd() -> None:
    """Show whether the trust plane is engaged + the registered-agent count."""
    from .. import agent_trust
    st = agent_trust.status()
    state = click.style("ENGAGED", fg="green") if st["enforced"] else click.style(
        "disengaged", fg="yellow")
    click.echo(f"agent trust plane: {state}  ({st['count']} agent(s))")
    if st["enforced"] and st["count"] == 0:
        click.echo(click.style(
            "  ! engaged with an EMPTY registry — every external agent is denied",
            fg="red"))


@trust_group.command("list")
def trust_list_cmd() -> None:
    """List trusted external agents (id, direction, key, risk, scopes, active)."""
    from .. import agent_trust
    reg = agent_trust.load_registry()
    if not reg:
        click.echo("(no trusted agents configured)")
        return
    for a in reg.values():
        active, why = a.is_active()
        flag = click.style("active", fg="green") if active else click.style(
            why, fg="red")
        key = (a.pubkey[:12] + "…") if a.pubkey else click.style("no-key", fg="yellow")
        click.echo(f"  {a.id:24}  {a.direction:8}  key={key}  "
                   f"risk={a.max_risk or 'any'}  scopes={sorted(a.data_scopes) or '-'}  "
                   f"[{flag}]")


@trust_group.command("show")
@click.argument("agent_id")
def trust_show_cmd(agent_id: str) -> None:
    """Show one agent's full trust entry."""
    from .. import agent_trust
    a = agent_trust.lookup(agent_id)
    if a is None:
        raise click.ClickException(f"no trusted agent {agent_id!r}")
    active, why = a.is_active()
    click.echo(f"id:           {a.id}")
    click.echo(f"direction:    {a.direction}")
    click.echo(f"pubkey:       {a.pubkey or '(none — token-only, discouraged)'}")
    click.echo(f"allow_tools:  {sorted(a.allow_tools) or '(all)'}")
    click.echo(f"deny_tools:   {sorted(a.deny_tools) or '-'}")
    click.echo(f"max_risk:     {a.max_risk or 'any'}")
    click.echo(f"max_dollars:  {a.max_dollars if a.max_dollars is not None else '-'}")
    click.echo(f"data_scopes:  {sorted(a.data_scopes) or '-'}")
    click.echo(f"active:       {active} ({why})")


@trust_group.command("pubkey")
def trust_pubkey_cmd() -> None:
    """Print THIS deployment's pinned Ed25519 public key (hand to peers)."""
    from .. import agent_trust
    pk = agent_trust.local_pubkey()
    if not pk:
        raise click.ClickException(
            "no audit key available (install the [audit-signing] extra)")
    click.echo(pk)


@trust_group.command("add")
@click.argument("agent_id")
@click.option("--pubkey", default="", help="Pinned Ed25519 public key (hex).")
@click.option("--direction", type=click.Choice(["inbound", "outbound", "both"]),
              default="both")
@click.option("--allow-tools", default="", help="Comma-separated tool allowlist.")
@click.option("--max-risk", type=click.Choice(["low", "medium", "high"]), default=None)
@click.option("--max-dollars", type=float, default=None)
@click.option("--data-scopes", default="", help="Comma-separated memory scopes.")
@click.option("--a2a-token", default="", help="Per-caller A2A bearer.")
@click.option("--grpc-token", default="", help="Per-caller gRPC bearer.")
@click.option("--mcp-token", default="", help="Per-caller MCP bearer.")
def trust_add_cmd(agent_id, pubkey, direction, allow_tools, max_risk, max_dollars,
                  data_scopes, a2a_token, grpc_token, mcp_token) -> None:
    """Add or replace a trusted external agent (managed overlay)."""
    from .. import agent_trust

    def _split(s):
        return [x.strip() for x in s.split(",") if x.strip()]

    def _at_rest(token):
        # The managed overlay must never hold a raw bearer (a leaked backup
        # of it must not authenticate); store the hashed form `mint` uses.
        if not token or token.startswith("sha256:"):
            return token
        return agent_trust.hash_token(token)

    entry = {
        "id": agent_id, "pubkey": pubkey, "direction": direction,
        "allow_tools": _split(allow_tools), "max_risk": max_risk,
        "max_dollars": max_dollars, "data_scopes": _split(data_scopes),
        "a2a_token": _at_rest(a2a_token), "grpc_token": _at_rest(grpc_token),
        "mcp_token": _at_rest(mcp_token),
    }
    try:
        a = agent_trust.put_agent(entry)
    except agent_trust.AgentTrustError as e:
        raise click.ClickException(str(e)) from e
    click.echo(click.style(f"trusted agent {a.id!r} saved", fg="green"))


@trust_group.command("rm")
@click.argument("agent_id")
def trust_rm_cmd(agent_id: str) -> None:
    """Remove a managed trusted agent."""
    from .. import agent_trust
    from ..revocation import ProtectedRevocationError, shared

    # Removing a contained agent's entry drops its revoked flag, so a later
    # `trust add` would re-admit it without the security release.
    action_errors: list[Exception] = []

    def _remove() -> bool:
        try:
            return agent_trust.remove_agent(agent_id)
        except Exception as exc:  # reported below, not as a containment failure
            action_errors.append(exc)
            return False

    try:
        removed = shared().run_if_unprotected(f"agent:{agent_id}", _remove)
    except ProtectedRevocationError as exc:
        raise click.ClickException(
            "agent is security-contained; use `maverick control-plane release`"
        ) from exc
    except Exception as exc:
        raise click.ClickException(
            "containment authority is unavailable; remove refused"
        ) from exc
    if action_errors:
        raise click.ClickException(
            f"could not remove {agent_id!r}: {action_errors[0]}") from action_errors[0]
    if removed:
        click.echo(click.style(f"removed {agent_id!r}", fg="yellow"))
    else:
        raise click.ClickException(
            f"no managed agent {agent_id!r} (hand-edited [agent_trust] entries "
            "are removed from config.toml)")


@trust_group.command("revoke")
@click.argument("agent_id")
def trust_revoke_cmd(agent_id: str) -> None:
    """Revoke a trusted agent immediately (denied even mid-rotation)."""
    from .. import agent_trust
    if not agent_trust.lookup(agent_id):
        raise click.ClickException(f"no trusted agent {agent_id!r}")
    if agent_trust.set_revoked(agent_id, True):
        click.echo(click.style(f"revoked {agent_id!r}", fg="yellow"))
    else:
        raise click.ClickException(
            f"{agent_id!r} is a hand-edited config entry — set revoked = true in "
            "[agent_trust], or re-add it via `maverick trust add` to manage it")


@trust_group.command("unrevoke")
@click.argument("agent_id")
def trust_unrevoke_cmd(agent_id: str) -> None:
    """Lift a revocation on a managed agent."""
    from .. import agent_trust
    from ..revocation import ProtectedRevocationError, RevocationStoreError, shared
    try:
        changed = shared().run_if_unprotected(
            f"agent:{agent_id}",
            lambda: agent_trust.set_revoked(agent_id, False),
        )
    except ProtectedRevocationError as exc:
        raise click.ClickException(
            "agent is security-contained; use `maverick control-plane release`"
        ) from exc
    except (RevocationStoreError, RuntimeError, OSError) as exc:
        raise click.ClickException(
            "containment authority is unavailable; unrevocation refused"
        ) from exc
    except agent_trust.AgentTrustError as exc:
        raise click.ClickException(str(exc)) from exc
    if changed:
        click.echo(click.style(f"unrevoked {agent_id!r}", fg="green"))
    else:
        raise click.ClickException(f"no managed agent {agent_id!r}")


@trust_group.command("verify")
@click.argument("agent_id")
@click.option("--tools", default="", help="Comma-separated required tools.")
@click.option("--risk", type=click.Choice(["low", "medium", "high"]), default=None)
@click.option("--direction", type=click.Choice(["inbound", "outbound"]),
              default="inbound")
def trust_verify_cmd(agent_id, tools, risk, direction) -> None:
    """Replay the trust decision for AGENT_ID and print allow/deny + reason."""
    from .. import agent_trust
    req = [x.strip() for x in tools.split(",") if x.strip()]
    if direction == "outbound":
        d = agent_trust.decide_outbound(agent_id, enforced=True)
    else:
        d = agent_trust.decide_inbound(agent_id, requested_tools=req, max_risk=risk,
                                       enforced=True)
    verdict = click.style("ALLOW", fg="green") if d.allowed else click.style(
        "DENY", fg="red")
    click.echo(f"{direction} {agent_id!r}: {verdict}  rule={d.rule}  {d.reason}")


@main.group("client")
def client_group() -> None:
    """Inspect, export, or erase this installation's bound local client data.

    Export and erase cover the bound tenant folder on this computer. Stop
    Lightwork before erasing; other workspaces, connected services, and saved
    copies need separate review and removal."""


@client_group.command("status")
def client_status_cmd() -> None:
    """Show the client binding + data root."""
    from ..client import status as client_status
    st = client_status()
    if st["bound"]:
        click.echo(click.style(f"bound to {st['client_id']!r}", fg="green")
                   + f"  (enforced={st['enforced']})")
        click.echo(f"data root: {st['data_root']}")
    else:
        msg = "NOT bound to a client (shared root)"
        click.echo(click.style(msg, fg="red" if st["enforced"] else "yellow"))


@client_group.command("export")
@click.option("--out", default=None, help="Destination .tgz (default: under data root).")
def client_export_cmd(out) -> None:
    """Export all of this client's data (data portability / DSAR)."""
    from ..backup import BackupError, create_backup
    try:
        path = create_backup(out)
    except BackupError as e:
        raise click.ClickException(str(e)) from e
    click.echo(click.style(f"client export written: {path}", fg="green"))


@client_group.command("erase")
@click.option("--confirm", is_flag=True, help="Required: actually erase the data.")
@click.option("--keep-audit", is_flag=True,
              help="Preserve the signed audit chain (legal retention).")
def client_erase_cmd(confirm, keep_audit) -> None:
    """Erase this client's bound local folder while Lightwork is stopped.

    Removes the bound tenant's world DB, memory, fleet, trust registry, and
    — unless --keep-audit — activity record. Other workspaces, connected
    services, and saved exports or backups are outside this command's scope.
    A signed operation receipt survives outside the folder. Irreversible:
    stop every writer and export first."""
    from ..client import ClientBindingError, ClientErasureError, client_id, erase_client
    cid = client_id()
    if not cid:
        raise click.ClickException("no client bound — refusing to erase the shared root")
    if not confirm:
        raise click.ClickException(
            f"this ERASES the local tenant folder for client {cid!r} and is irreversible. "
            "Re-run with --confirm (and consider `maverick client export` first).")
    try:
        res = erase_client(keep_audit=keep_audit)
    except (ClientBindingError, ClientErasureError) as e:
        raise click.ClickException(str(e)) from e
    click.echo(click.style(
        f"erased local data for client {res['client_id']!r}: {res['removed']} path(s) removed"
        + (" (audit kept)" if res["kept_audit"] else ""), fg="yellow"))
    click.echo(f"Activity receipt: {res['audit_event_id']} ({res['receipt_path']})")


@main.group("backup")
def backup_group() -> None:
    """Back up / restore this client's data for DR + standby failover.

    Snapshots the client-scoped data root (world DB via the SQLite online backup
    API, signed audit chain, memory, fleet, managed trust registry) into a
    portable ``.tgz`` with an authenticated manifest. The at-rest encryption
    key, audit signing key and browser vault key are excluded by default (escrow them
    separately per docs/encryption.md; ``--include-keys`` opts back in). Set
    the same 32-byte ``MAVERICK_BACKUP_SIGNING_KEY`` on the active and
    standby nodes. Restore is transactional and fail-closed on
    authenticity, bounds, and client id."""


@backup_group.command("create")
@click.option("--out", default=None, help="Destination .tgz (default: under data root).")
@click.option("--include-keys", is_flag=True,
              help="Bundle the at-rest encryption, audit signing and browser "
                   "vault key material in the archive. Off by default: escrow keys separately "
                   "instead of storing them next to the data they unlock.")
def backup_create_cmd(out, include_keys) -> None:
    """Create a consistent backup of this client's data."""
    from ..backup import BackupError, create_backup, withheld_key_files
    if include_keys:
        click.echo(click.style(
            "WARNING: --include-keys bundles the at-rest encryption, audit "
            "signing and browser vault key material inside this archive. Anyone who obtains a "
            "copy (offsite backup, object storage, a lost disk) gets "
            "plaintext-equivalent access to everything it seals. Escrow keys "
            "separately unless you have a specific reason not to.",
            fg="yellow"))
    try:
        path = create_backup(out, include_keys=include_keys)
    except BackupError as e:
        raise click.ClickException(str(e)) from e
    if not include_keys:
        try:
            left_out = withheld_key_files()
        except OSError:  # the list is advice; the backup itself is already written
            left_out = []
        if left_out:
            click.echo(click.style(
                "Key files left out of this backup. Keep a separate, safe copy "
                "of each: the encryption keys among them are needed to open "
                "this backup's protected data:", fg="yellow"))
            for name in left_out:
                click.echo(f"  {name}")
    click.echo(click.style(f"backup written: {path}", fg="green"))


@backup_group.command("restore")
@click.argument("tarball")
@click.option("--force", is_flag=True,
              help="Restore even if the backup's client id differs, or the "
                   "live world database still appears open (dangerous).")
def backup_restore_cmd(tarball, force) -> None:
    """Restore TARBALL into this client's data root (fail-closed on client id).

    Stop `maverick serve` / the dashboard first: restoring while a process
    still has the world database open silently loses every write made
    through that connection until it restarts. --force overrides the check.
    """
    from ..backup import BackupError, restore_backup
    try:
        root = restore_backup(tarball, force=force)
    except BackupError as e:
        raise click.ClickException(str(e)) from e
    click.echo(click.style(f"restored into {root}", fg="green"))


@backup_group.command("info")
@click.argument("tarball")
def backup_info_cmd(tarball) -> None:
    """Show a backup's manifest (client id, time, file count, schema version)."""
    from ..backup import BackupError, read_manifest
    try:
        m = read_manifest(tarball)
    except BackupError as e:
        raise click.ClickException(str(e)) from e
    import datetime
    when = datetime.datetime.fromtimestamp(
        m.get("created_at", 0), datetime.timezone.utc).isoformat()
    click.echo(f"client_id:            {m.get('client_id')}")
    click.echo(f"created_at:           {when}")
    click.echo(f"world_schema_version: {m.get('world_schema_version')}")
    click.echo(f"files:                {len(m.get('files') or {})}")


@main.group("attest")
def attest_group() -> None:
    """Portable attestation: prove past behaviour to somebody who trusts nobody.

    A bundle binds three claims -- actions stayed inside the declared policy
    envelope, self-improvement never widened its own authority, the decision
    history is intact -- to evidence a third party can re-derive. Verification
    requires the publisher's key obtained OUT OF BAND (``attest key``); a key
    read out of the bundle proves only that somebody signed it.
    """


@attest_group.command("key")
def attest_key_cmd() -> None:
    """Print this instance's public key -- publish it out of band."""
    from ..attestation import publisher_key
    key_id, pub = publisher_key()
    click.echo(f"key_id: {key_id}")
    click.echo(f"pubkey: {pub}")
    click.echo("")
    click.echo("Give a verifier this key through a channel that does NOT run "
               "through the bundle (key page, contract, existing engagement).")


@attest_group.command("export")
@click.argument("out", type=click.Path())
@click.option("--since", type=float, default=None,
              help="Unix timestamp bounding the promotion window.")
@click.option("--audit-dir", type=click.Path(), default=None,
              help="Audit directory to attest (default: this instance's).")
def attest_export_cmd(out: str, since: float | None, audit_dir: str | None) -> None:
    """Build and sign an attestation bundle at OUT."""
    from ..attestation import export
    try:
        path = export(out, audit_dir=audit_dir, since=since)
    except RuntimeError as e:
        raise click.ClickException(str(e)) from e
    click.echo(f"attestation -> {path}")
    import json as _json
    bundle = _json.loads(path.read_text(encoding="utf-8"))
    for warning in bundle.get("warnings") or []:
        click.echo(click.style(f"  ! {warning}", fg="yellow"))


@attest_group.command("verify")
@click.argument("bundle", type=click.Path(exists=True))
@click.option("--key", "key_hex", default="", metavar="HEX",
              help="Publisher's Ed25519 public key, obtained OUT OF BAND.")
@click.option("--evidence", type=click.Path(), default=None,
              help="Audit directory, to check commitments against the files.")
def attest_verify_cmd(bundle: str, key_hex: str, evidence: str | None) -> None:
    """Verify BUNDLE against a trusted key (fails closed without one)."""
    from ..attestation import verify
    from ..attestation_verify import format_report
    result = verify(bundle, trusted_key_hex=key_hex, evidence_root=evidence)
    click.echo(format_report(result))
    if not result.ok:
        raise click.ClickException("attestation verification failed")


@attest_group.command("export-verifier")
@click.argument("out", type=click.Path())
def attest_export_verifier_cmd(out: str) -> None:
    """Write the standalone verifier to OUT (runs with no maverick install)."""
    import pathlib

    from ..attestation import verifier_source
    text, digest = verifier_source()
    path = pathlib.Path(out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    click.echo(f"verifier -> {path}")
    click.echo(f"sha256:     {digest}")
    click.echo("")
    click.echo(f"  python {path.name} <bundle.json> --key <pubkey-hex> "
               "[--evidence <audit-dir>]")
    click.echo("Needs only Python and 'cryptography'.")


@main.group("security")
def security_group() -> None:
    """Agent-EDR: detect, contain and prove compromise across the fleet.

    Reads detections off the audit chain with explicit signature posture,
    contains a compromised agent
    in one act, and prints a forensic timeline. Every command reports the
    deployment's POSTURE alongside its findings: an empty detection list from a
    deployment with the shield off means "not watched", not "not attacked".
    """


@security_group.command("posture")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def security_posture_cmd(as_json: bool) -> None:
    """Which defenses are actually switched on."""
    import json as _json

    from ..agent_edr import posture
    p = posture().to_dict()
    if as_json:
        click.echo(_json.dumps(p, indent=2))
        return
    for name in ("shield", "capabilities", "audit_signing", "agent_trust",
                 "egress_control"):
        on = p.get(name)
        click.echo(f"  {name:16} {'ON' if on else 'off'}"
                   if on else click.style(f"  {name:16} off", fg="yellow"))
    for note in p.get("notes") or []:
        click.echo(click.style(f"  ! {note}", fg="yellow"))


@security_group.command("detections")
@click.option("--subject", default="", help="Filter to one principal.")
@click.option("--min-severity", default="low",
              type=click.Choice(["low", "medium", "high"]))
@click.option("--limit", default=500, show_default=True,
              help="Maximum detections to sweep and show.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def security_detections_cmd(subject: str, min_severity: str, limit: int,
                            as_json: bool) -> None:
    """Security detections from the audit chain, newest first.

    Uses ``scan`` rather than ``detections`` so the operator surface -- the one
    place completeness actually matters -- can say when the sweep was bounded
    or read unsigned rows, instead of printing a capped list that looks total.
    """
    import json as _json

    from ..agent_edr import posture, scan, summary
    swept = scan(subject=subject, min_severity=min_severity, limit=limit)
    if as_json:
        click.echo(_json.dumps(
            {"posture": posture().to_dict(),
             "summary": summary(swept.found),
             "truncated": swept.truncated,
             "unsigned_rows": swept.unsigned_rows,
             "unreadable_days": swept.unreadable_days,
             "evidence_is_signed": swept.evidence_is_signed,
             "detections": [d.to_dict() for d in swept.found]},
            indent=2, default=str))
        return
    blind = posture().blind_spots
    if blind:
        click.echo(click.style(
            f"! defenses OFF: {', '.join(blind)} — absence of detections "
            "across these proves nothing", fg="yellow"))
    for d in swept.found:
        click.echo(f"  [{d.severity:8}] {d.kind:18} {d.subject:24} {d.detail}")
    click.echo(f"{len(swept.found)} detection(s)")
    if swept.truncated:
        click.echo(click.style(
            f"! the sweep stopped at --limit {limit}: OLDER detections exist "
            "that are not shown", fg="yellow"))
    if swept.unsigned_rows:
        click.echo(click.style(
            f"! {swept.unsigned_rows} row(s) are unsigned: this list is not "
            "tamper-evident", fg="yellow"))
    if swept.unreadable_days:
        click.echo(click.style(
            f"! {len(swept.unreadable_days)} day-file(s) unreadable: this list "
            "is partial", fg="yellow"))


@security_group.command("contain")
@click.argument("subject")
@click.option("--reason", default="", help="Why this agent is being contained.")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def security_contain_cmd(subject: str, reason: str, yes: bool) -> None:
    """Revoke SUBJECT's authority (durable) and record the response.

    Run from the CLI there is no live swarm to seal, so this revokes future
    authority; it does not stop an agent already mid-run in another process.
    The output says so rather than reporting a containment it did not achieve.
    """
    from ..agent_edr import contain
    if not yes:
        click.confirm(f"Revoke all authority for {subject!r}?", abort=True)
    result = contain(subject, reason=reason or "operator containment")
    colour = "green" if result.contained else "red"
    click.echo(click.style(
        f"contained={result.contained}  revoked={len(result.revoked)}", fg=colour))
    for note in result.notes:
        click.echo(click.style(f"  - {note}", fg="yellow"))
    for failure in result.failed:
        click.echo(click.style(f"  ! {failure}", fg="red"))
    if not result.contained:
        raise click.ClickException("containment did not fully succeed")


@security_group.command("release")
@click.argument("subject")
def security_release_cmd(subject: str) -> None:
    """Undo a containment for SUBJECT."""
    from ..agent_control_plane import is_external
    from ..agent_edr import release
    if is_external(subject):
        # This path lifts only the revocation row; an external agent's trust
        # entry and gateway containment would stay in force while it printed
        # success. The control plane releases all three together.
        raise click.ClickException(
            "an external agent's trust entry and gateway containment are lifted "
            "together by the control plane: enable it ([control_plane] enable = "
            "true or MAVERICK_CONTROL_PLANE=1), then run "
            f"`maverick control-plane release {subject}`")
    result = release(subject)
    colour = "green" if result.contained else "red"
    click.echo(click.style(f"released={result.contained}", fg=colour))
    for note in result.notes:
        click.echo(f"  - {note}")
    for failure in result.failed:
        click.echo(click.style(f"  ! {failure}", fg="red"))
    if not result.contained:
        # `contain` already exits non-zero on failure. Without the same here a
        # runbook doing `maverick security release X && echo done` reports
        # success while the agent is still locked out.
        raise click.ClickException("release did not fully succeed")


@security_group.command("incident")
@click.argument("subject")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def security_incident_cmd(subject: str, as_json: bool) -> None:
    """Forensic incident report for SUBJECT."""
    import json as _json

    from ..agent_edr import incident_report, render_report
    report = incident_report(subject)
    click.echo(_json.dumps(report, indent=2, default=str) if as_json
               else render_report(report))


@main.group("memory-plane")
def memory_plane_group() -> None:
    """The Institutional Memory plane: attest what the fleet actually learned.

    Signs a portable statement of the plane's cross-vendor activity, its
    compounding curve per department, and its tenant binding. Verification
    needs the publisher's key obtained out of band (``maverick attest key``).
    """


@memory_plane_group.command("compounding")
@click.option("--window", default=5, show_default=True,
              help="Runs per cold/warm window.")
@click.pass_context
def memory_plane_compounding_cmd(ctx, window: int) -> None:
    """Cold-vs-warm cost and reliability, per department."""
    from ..memory_plane import compounding_by_department
    world = open_world(ctx.obj["db"])
    curves = compounding_by_department(world, window=window)
    if not curves:
        click.echo("no department has enough runs yet — the curve would be "
                   "noise rather than evidence")
        return
    for c in curves:
        arrow = click.style("compounding", fg="green") if c.improving else \
            click.style("not yet", fg="yellow")
        click.echo(f"  {c.department:22} runs={c.runs:<5} "
                   f"${c.cold_cost:.4f} -> ${c.warm_cost:.4f}   {arrow}")


@memory_plane_group.command("export")
@click.argument("out", type=click.Path())
@click.pass_context
def memory_plane_export_cmd(ctx, out: str) -> None:
    """Build and sign a memory-plane attestation at OUT."""
    from ..memory_plane import export
    world = open_world(ctx.obj["db"])
    try:
        path = export(out, world)
    except RuntimeError as e:
        raise click.ClickException(str(e)) from e
    click.echo(f"memory-plane attestation -> {path}")
    import json as _json
    bundle = _json.loads(path.read_text(encoding="utf-8"))
    for warning in bundle.get("warnings") or []:
        click.echo(click.style(f"  ! {warning}", fg="yellow"))


@memory_plane_group.command("verify")
@click.argument("bundle", type=click.Path(exists=True))
@click.option("--key", "key_hex", default="", metavar="HEX",
              help="Publisher's Ed25519 public key, obtained OUT OF BAND.")
def memory_plane_verify_cmd(bundle: str, key_hex: str) -> None:
    """Verify BUNDLE against a trusted key (fails closed without one)."""
    from ..attestation_verify import format_report
    from ..memory_plane import verify_file
    result = verify_file(bundle, trusted_key_hex=key_hex)
    click.echo(format_report(result))
    if not result.ok:
        raise click.ClickException("memory-plane verification failed")


# ---- trust receipts ---------------------------------------------------------

@attest_group.group("receipt")
def receipt_group() -> None:
    """Bearer-verifiable receipts for single audited decisions.

    A receipt binds ONE signed audit row -- "tool X was denied under rule R",
    "tool X was attempted", or an ok result that says "tool X executed" -- to
    the chain it sits in and (with ``--checkpoint-dir``) to
    a signed checkpoint whose digest the operator publishes out of band. A
    third party verifies it offline with ``receipt export-verifier`` and the
    publisher's key from ``attest key``; nothing is trusted from inside the
    receipt itself.
    """


@receipt_group.command("mint")
@click.argument("day")
@click.argument("row_hash")
@click.option("--out", "-o", "out", type=click.Path(), required=True,
              help="Where to write the receipt JSON.")
@click.option("--audit-dir", type=click.Path(), default=None,
              help="Audit directory holding the day-file (default: this instance's).")
@click.option("--checkpoint-dir", type=click.Path(), default=None,
              help="Publish (or reuse) a signed checkpoint committing to the "
                   "row's chain (issuer evidence at depth 'chained'). Publish "
                   "and retain its digest separately to reach 'anchored'.")
@click.option("--include-chain/--no-suffix", default=False,
              help="DISCLOSURE OPT-IN: include every later full audit row needed "
                   "to walk the linear chain. Default --no-suffix prevents a "
                   "one-row receipt from exposing unrelated same-day activity.")
@click.option("--include-execution-pair", is_flag=True,
              help="DISCLOSURE OPT-IN for a tool-result receipt: include its one "
                   "full signed call row (including input_summary) to prove a "
                   "committed call/result pair.")
def receipt_mint_cmd(day: str, row_hash: str, out: str, audit_dir: str | None,
                     checkpoint_dir: str | None, include_chain: bool,
                     include_execution_pair: bool) -> None:
    """Mint a signed receipt for the audit row ROW_HASH recorded on DAY."""
    from ..trust_receipt import export
    from ..trust_receipt_verify import load_receipt
    try:
        path = export(out, audit_dir=audit_dir, day=day, row_hash=row_hash,
                      checkpoint_dir=checkpoint_dir, include_suffix=include_chain,
                      include_execution_pair=include_execution_pair)
    except (LookupError, OSError, ValueError, RuntimeError) as e:
        raise click.ClickException(str(e)) from e
    try:
        receipt = load_receipt(path)
    except Exception as exc:
        raise click.ClickException(
            f"receipt was published at {path}, but its metadata could not be "
            "read back safely"
        ) from exc
    click.echo(f"receipt -> {path}")
    claim = receipt.get("claim") or {}
    click.echo(f"claim:      {claim.get('decision')} {claim.get('tool') or ''}".rstrip())
    if (receipt.get("disclosure") or {}).get("execution_pair_included"):
        click.echo(click.style(
            "disclosure: one full signed TOOL_CALL row, including its bounded "
            "input_summary", fg="yellow"))
    commitment = receipt.get("commitment") or {}
    chain = receipt.get("chain") or {}
    locator = receipt.get("locator") or {}
    suffix = chain.get("suffix_ndjson") or []
    chain_walkable = (
        isinstance(locator.get("position"), int)
        and isinstance(chain.get("row_count"), int)
        and locator["position"] + len(suffix) == chain["row_count"]
    )
    if commitment.get("source") == "checkpoint":
        click.echo(f"checkpoint: #{commitment.get('sequence')} "
                   f"sha256={commitment.get('raw_sha256')}")
        if chain_walkable:
            click.echo("Publish that digest out of band; a verifier passes it as "
                       "--anchor-digest to reach depth 'anchored'.")
        else:
            click.echo(click.style(
                "privacy-safe receipt omitted later audit rows, so the checkpoint "
                "cannot be reached from this row. Re-mint with --include-chain "
                "only with recipient disclosure approval if anchored depth is "
                "required.", fg="yellow"))
    elif commitment.get("source") == "anchor_ledger":
        if chain_walkable:
            click.echo("committed by the issuer's anchor ledger (depth 'chained'; "
                       "pass --checkpoint-dir for an externally anchorable receipt)")
        else:
            click.echo("issuer anchor exists, but the privacy-safe receipt omits "
                       "later rows and therefore verifies at depth 'signed' only")
    else:
        click.echo(click.style(
            "no commitment: verifiable at depth 'signed' only "
            "(pass --checkpoint-dir to create a publishable checkpoint "
            "commitment)", fg="yellow"))


@receipt_group.command("verify")
@click.argument("receipt", type=click.Path(exists=True))
@click.option("--key", "keys", multiple=True, metavar="HEX",
              help="CURRENT receipt-issuer Ed25519 key obtained OUT OF BAND.")
@click.option("--history-key", "history_keys", multiple=True, metavar="HEX",
              help="Retired key trusted only for historical audit rows.")
@click.option("--checkpoint-key", "checkpoint_keys", multiple=True, metavar="HEX",
              help="Current checkpoint-authority key (defaults to --key).")
@click.option("--anchor-digest", default=None, metavar="SHA256",
              help="Published sha256 of the checkpoint file the receipt cites.")
@click.option("--checkpoint-dir", type=click.Path(), default=None,
              help="Issuer checkpoint directory for byte comparison only; it "
                   "does not independently anchor history. Use a retained "
                   "--anchor-digest for anchored depth.")
@click.option("--require-depth", type=click.Choice(["signed", "chained", "anchored"]),
              default=None,
              help="Reject a valid receipt below this proof depth. "
                   "--anchor-digest implicitly requires anchored depth.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def receipt_verify_cmd(receipt: str, keys: tuple[str, ...],
                       history_keys: tuple[str, ...],
                       checkpoint_keys: tuple[str, ...],
                       anchor_digest: str | None, checkpoint_dir: str | None,
                       require_depth: str | None, as_json: bool) -> None:
    """Verify RECEIPT against trusted keys (fails closed without one)."""
    import json as _json

    from ..trust_receipt import verify
    from ..trust_receipt_verify import format_report
    result = verify(
        receipt,
        trusted_keys=keys,
        historical_keys=history_keys,
        checkpoint_keys=checkpoint_keys or None,
        anchor_digest=anchor_digest,
        checkpoint_dir=checkpoint_dir,
        require_depth=require_depth,
    )
    click.echo(_json.dumps(result.to_dict(), indent=2) if as_json
               else format_report(result))
    if not result.ok:
        raise click.ClickException("trust receipt verification failed")


@receipt_group.command("export-verifier")
@click.argument("out", type=click.Path())
def receipt_export_verifier_cmd(out: str) -> None:
    """Write the standalone receipt verifier to OUT (no maverick install needed)."""
    import pathlib

    from ..file_lock import atomic_create_bytes
    from ..trust_receipt import verifier_source
    path = pathlib.Path(out)
    try:
        text, digest = verifier_source()
        raw = text.encode("utf-8")
        atomic_create_bytes(path, raw, mode=0o600)
    except FileExistsError as exc:
        raise click.ClickException(
            f"refusing to overwrite existing verifier path: {path}"
        ) from exc
    except Exception as exc:
        raise click.ClickException(
            f"could not export verifier safely to {path}"
        ) from exc
    click.echo(f"verifier -> {path}")
    click.echo(f"sha256:     {digest}")
    click.echo("")
    click.echo(f"  python {path.name} <receipt.json> --key <current-pubkey-hex> "
               "[--history-key <retired-row-key>] [--anchor-digest <sha256>] "
               "[--checkpoint-dir <dir>]")
    click.echo("Needs only Python and 'cryptography'.")
