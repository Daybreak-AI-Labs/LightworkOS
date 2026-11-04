"""``maverick ekko`` -- explicit, local-first work discovery lifecycle."""
from __future__ import annotations

import json
import signal
import time
from functools import wraps
from pathlib import Path
from typing import Any

import click

from ..work_discovery_identity import local_os_principal
from . import main


def _store(owner: str, device_id: str):
    from ..work_discovery_store import WorkDiscoveryStore

    # Tenant is resolved server-side from the active CLI context. There is no
    # --tenant payload knob on purpose: a caller may not select another
    # client's capture ledger through this command group.
    return WorkDiscoveryStore(owner=owner, device_id=device_id)


def _identity_options(func):
    @wraps(func)
    def bound_identity(*args, **kwargs):
        kwargs["owner"] = local_os_principal()
        return func(*args, **kwargs)

    return click.option(
        "--device", "device_id", required=True,
        help="Client-assigned device ID (stored only as a scoped digest).",
    )(bound_identity)


def _to_dict(value: Any) -> Any:
    if value is None:
        return None
    method = getattr(value, "to_dict", None)
    return method() if callable(method) else value


def _emit_json(value: Any) -> None:
    click.echo(json.dumps(value, sort_keys=True, indent=2))


def _audit(kind: str, *, required: bool = False, **payload: Any) -> bool:
    """Record content-free lifecycle state; observation authority fails closed."""
    try:
        from ..audit import record

        persisted = bool(record(kind, agent="ekko-cli", **payload))
    except Exception:
        persisted = False
    if required and not persisted:
        raise click.ClickException(
            "Ekko authorization audit could not be persisted"
        )
    return persisted


def _parse_apps(value: str | None) -> list[str] | None:
    if value is None:
        return None
    result: list[str] = []
    seen: set[str] = set()
    for item in value.split(","):
        app = item.strip().casefold()
        if app and app not in seen:
            seen.add(app)
            result.append(app)
    if not result:
        raise click.BadParameter(
            "must name at least one canonical app, or omit --apps to use the "
            "configured ceiling",
            param_hint="--apps",
        )
    return result


def _latest_session(store):
    session = store.latest_session()
    if session is None:
        raise click.ClickException("no Ekko session exists for this owner and device")
    return session


def _enrolled_policy(store):
    from ..config import validate_ekko_policy_ceiling

    policy = store.get_policy()
    if policy is None:
        raise click.ClickException(
            "no active, unexpired enrollment policy; run `maverick ekko enroll`"
        )
    try:
        validate_ekko_policy_ceiling(policy)
    except (TypeError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    return policy


@main.group("ekko")
def ekko_group() -> None:
    """Discover repeatable work under explicit client enrollment.

    Ekko is off by default. It never starts at login, selects an ambient
    observer, requests OS permissions, saves a draft, or activates automation.
    """


@ekko_group.command("status")
@_identity_options
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
def ekko_status(owner: str, device_id: str, as_json: bool) -> None:
    """Show policy, enrollment, session, and local event count."""
    from ..config import get_ekko

    store = _store(owner, device_id)
    status = store.status()
    status["config"] = get_ekko()
    if as_json:
        _emit_json(status)
        return
    cfg = status["config"]
    enrollment = status.get("enrollment")
    session = status.get("session")
    click.echo(f"policy: {'enabled' if cfg['enable'] else 'off'}")
    if enrollment:
        state = "active" if enrollment.get("active") else "revoked"
        expiry = enrollment.get("expires_at")
        suffix = f"; expires {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime(expiry))}" if expiry else ""
        click.echo(f"enrollment: {state}{suffix}")
    else:
        click.echo("enrollment: none")
    if session:
        click.echo(
            f"session: {session['state']} ({session['session_id']}; "
            f"{session['last_sequence']} event(s))"
        )
    else:
        click.echo("session: none")
    collector = status.get("collector") or {}
    click.echo(f"collector: {collector.get('state', 'waiting')}")
    click.echo(f"local events: {status.get('event_count', 0)}")


@ekko_group.command("enroll")
@_identity_options
@click.option(
    "--apps", default=None,
    help="Comma-separated canonical app IDs; omit to use [ekko].allowed_apps.",
)
@click.option(
    "--days", type=click.IntRange(1, 90), default=None,
    help="Consent lifetime (1-90 days; default: [ekko].enrollment_days).",
)
def ekko_enroll(owner: str, device_id: str, apps: str | None, days: int | None) -> None:
    """Enroll one owner/device under the current admin policy ceiling."""
    from ..config import get_ekko, get_ekko_policy

    selected = _parse_apps(apps)
    try:
        policy = get_ekko_policy(allowed_apps=selected)
    except (TypeError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    lifetime = days if days is not None else int(get_ekko()["enrollment_days"])
    expires_at = time.time() + lifetime * 86_400
    from ..audit import EventKind

    _audit(
        EventKind.EKKO_CONSENT_CHANGED,
        required=True,
        state="enroll_authorized",
        policy_digest=policy.fingerprint(),
        expires_at=expires_at,
    )
    try:
        enrollment = _store(owner, device_id).enroll(
            policy, expires_at=expires_at,
        )
    except (TypeError, ValueError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(
        "enrolled: policy is local-only, expires "
        + time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(enrollment.expires_at))
    )
    _audit(
        EventKind.EKKO_CONSENT_CHANGED,
        state="enrolled",
        policy_digest=policy.fingerprint(),
        expires_at=enrollment.expires_at,
    )
    click.echo("next: start an explicit foreground observer with `maverick ekko run`")


@ekko_group.command("revoke")
@_identity_options
def ekko_revoke(owner: str, device_id: str) -> None:
    """Revoke consent and atomically stop active capture sessions."""
    enrollment = _store(owner, device_id).revoke_enrollment()
    from ..audit import EventKind

    _audit(EventKind.EKKO_CONSENT_CHANGED, state="revoked")
    click.echo("enrollment revoked; active sessions stopped" if enrollment else "no enrollment")


def _transition(owner: str, device_id: str, target: str) -> None:
    store = _store(owner, device_id)
    session = _latest_session(store)
    if target == "running":
        _enrolled_policy(store)
        from ..audit import EventKind

        _audit(
            EventKind.EKKO_SESSION,
            required=True,
            session_id=session.session_id,
            state="resume_authorized",
        )
    try:
        result = store.transition_session(session.session_id, target)
    except (TypeError, ValueError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc
    from ..audit import EventKind

    _audit(EventKind.EKKO_SESSION, session_id=result.session_id, state=target)
    click.echo(f"session {result.session_id}: {result.state.value}")


@ekko_group.command("pause")
@_identity_options
def ekko_pause(owner: str, device_id: str) -> None:
    """Pause the latest session; no event may append while paused."""
    _transition(owner, device_id, "paused")


@ekko_group.command("resume")
@_identity_options
def ekko_resume(owner: str, device_id: str) -> None:
    """Resume the latest session after policy and enrollment revalidation."""
    _transition(owner, device_id, "running")


@ekko_group.command("stop")
@_identity_options
def ekko_stop(owner: str, device_id: str) -> None:
    """Stop the latest session permanently; enrollment remains revocable."""
    _transition(owner, device_id, "stopped")


def _GuidedJsonlObserver(path: Path, *, follow: bool = False):  # noqa: N802 -- historical name
    from ..ekko_daemon import GuidedJsonlObserver

    return GuidedJsonlObserver(path, follow=follow)


def _selected_observer_kind(observer_name: str | None) -> str:
    from ..ekko_foreground import foreground_options

    return foreground_options()["observer"] or str(observer_name)


def _observer_from_options(events: Path | None, observer_name: str | None, follow: bool):
    if events is not None and observer_name is not None:
        raise click.UsageError("--events and --observer are mutually exclusive")
    if events is not None:
        return _GuidedJsonlObserver(events, follow=follow)
    if observer_name in {"windows", "macos", "linux-x11", "desktop"}:
        try:
            from ..ekko_foreground import foreground_observer, foreground_options

            expected = {"windows": "windows_foreground", "macos": "macos_foreground",
                        "linux-x11": "linux_x11_foreground"}.get(observer_name)
            if expected and foreground_options()["observer"] != expected:
                raise OSError("the selected platform recorder is unavailable")
            return foreground_observer()
        except (ImportError, OSError, RuntimeError) as exc:
            raise click.ClickException(
                "the selected desktop recorder is unavailable on this computer"
            ) from exc
    raise click.UsageError(
        "choose an explicit observer: --events FILE or --observer desktop"
    )


@ekko_group.command("run")
@_identity_options
@click.option(
    "--events", type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None, help="Strict guided JSONL event stream.",
)
@click.option(
    "--observer", "observer_name", type=click.Choice(["desktop", "windows", "macos", "linux-x11"]), default=None,
    help="Explicit platform observer (never selected automatically).",
)
@click.option(
    "--follow", is_flag=True,
    help="Wait for appended JSONL events instead of stopping at end-of-file.",
)
def ekko_run(
    owner: str, device_id: str, events: Path | None,
    observer_name: str | None, follow: bool,
) -> None:
    """Run an explicitly selected collector in the foreground."""
    if events is not None and observer_name is not None:
        raise click.UsageError("--events and --observer are mutually exclusive")
    if events is None and observer_name is None:
        raise click.UsageError(
            "choose an explicit observer: --events FILE or --observer desktop"
        )
    if follow and events is None:
        raise click.UsageError("--follow requires --events")
    store = _store(owner, device_id)
    policy = _enrolled_policy(store)
    if events is not None and policy.capture_level != "guided":
        raise click.ClickException(
            "guided JSONL requires capture_level = \"guided\" and re-enrollment"
        )
    from ..audit import EventKind

    _audit(
        EventKind.EKKO_SESSION,
        required=True,
        state="start_authorized",
        policy_digest=policy.fingerprint(),
        observer="guided_jsonl" if events is not None else _selected_observer_kind(observer_name),
    )
    observer = _observer_from_options(events, observer_name, follow)
    from ..ekko_daemon import EkkoDaemon

    daemon = EkkoDaemon(store=store, observer=observer, policy=policy)
    click.echo("Ekko is recording allowed application metadata. Ctrl-C to stop.")
    stop_requested = {"value": False}
    previous_sigterm = signal.getsignal(signal.SIGTERM)

    def request_stop(_signum, _frame):
        stop_requested["value"] = True

    sigterm_installed = False
    try:
        signal.signal(signal.SIGTERM, request_stop)
        sigterm_installed = True
    except ValueError:
        # Embedded CLI callers may invoke Click outside the main thread. The
        # foreground Ctrl-C path and durable lease expiry still stop capture.
        pass
    try:
        daemon.run(stop_when=lambda: (
            stop_requested["value"]
            or bool(getattr(observer, "exhausted", False))
        ))
    except KeyboardInterrupt:
        click.echo("\nstopping Ekko...")
    except (TypeError, ValueError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        try:
            try:
                daemon.stop()
            finally:
                if sigterm_installed:
                    signal.signal(signal.SIGTERM, previous_sigterm)
        finally:
            close = getattr(observer, "close", None)
            if callable(close):
                close()


@ekko_group.command("discover")
@_identity_options
@click.option(
    "--limit", type=click.IntRange(1, 20), default=20, show_default=True,
    help="Maximum opportunities to show.",
)
@click.option(
    "--drafts/--no-drafts", default=True,
    help="Include review-only Flow and Agent Factory first passes.",
)
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
def ekko_discover(
    owner: str, device_id: str, limit: int, drafts: bool, as_json: bool,
) -> None:
    """Mine repeated sequences and produce unsaved, review-only drafts."""
    from ..config import get_ekko
    from ..work_discovery import draft_bundle

    cfg = get_ekko()
    store = _store(owner, device_id)
    opportunities = store.discover(
        min_occurrences=cfg["min_occurrences"],
        min_distinct_days=cfg["min_distinct_days"],
    )[:limit]
    from ..audit import EventKind

    _audit(EventKind.EKKO_MINING_RUN, candidate_count=len(opportunities))
    rows: list[dict[str, Any]] = []
    for opportunity in opportunities:
        row = opportunity.to_dict()
        if drafts and opportunity.observation_basis != "application_metadata":
            row["draft"] = draft_bundle(opportunity, owner=owner).to_dict()
        elif drafts:
            row["next_step"] = "Open Ekko and describe the job, inputs, output and review before drafting."
        rows.append(row)
    if as_json:
        _emit_json({"opportunities": rows, "saved": False, "activated": False})
        return
    if not opportunities:
        click.echo("No repeated process meets the configured evidence floor yet.")
        return
    for opportunity in opportunities:
        click.echo(
            f"{opportunity.opportunity_id}  {opportunity.title}  "
            f"({opportunity.occurrences} occurrences / "
            f"{opportunity.distinct_days} days; task review required)"
        )
    click.echo("review-only: no agent, flow, schedule, or automation was saved or activated")


@ekko_group.command("erase")
@_identity_options
@click.option("--session", "session_id", default=None, help="Erase one session only.")
@click.option("--yes", is_flag=True, help="Required acknowledgement for irreversible erase.")
def ekko_erase(
    owner: str, device_id: str, session_id: str | None, yes: bool,
) -> None:
    """Irreversibly erase local raw work-discovery data."""
    if not yes:
        raise click.ClickException("refusing irreversible erase without --yes")
    try:
        counts = _store(owner, device_id).erase(session_id=session_id)
    except (TypeError, ValueError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc
    from ..audit import EventKind

    _audit(
        EventKind.EKKO_ERASE,
        scope="session" if session_id else "device",
        events=counts.get("events", 0),
        sessions=counts.get("sessions", 0),
    )
    click.echo(
        f"erased {counts.get('events', 0)} event(s) and "
        f"{counts.get('sessions', 0)} session(s)"
    )


@ekko_group.command("forget")
@_identity_options
@click.option(
    "--yes", is_flag=True,
    help="Required acknowledgement for consent revocation and irreversible erase.",
)
def ekko_forget(owner: str, device_id: str, yes: bool) -> None:
    """Revoke consent and remove all local records for this device."""
    if not yes:
        raise click.ClickException("refusing to forget a device without --yes")
    try:
        counts = _store(owner, device_id).forget_device()
    except (TypeError, ValueError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc
    from ..audit import EventKind

    _audit(
        EventKind.EKKO_ERASE,
        scope="forgot_device",
        events=counts.get("events", 0),
        sessions=counts.get("sessions", 0),
        enrollments=counts.get("enrollments", 0),
    )
    click.echo(
        "device forgotten: consent revoked; "
        f"{counts.get('events', 0)} event(s) and "
        f"{counts.get('sessions', 0)} session(s) erased"
    )


__all__ = ["ekko_group"]
