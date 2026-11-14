"""Lightwork's safety chokepoints, backed by Agent Shield with a built-in fallback.

The agent wraps three sinks through this module:
  - on every user input    -> Shield.scan_input
  - on every tool call     -> Shield.scan_tool_call
  - on every final output  -> Shield.scan_output

Backends (chosen automatically in order):
  1. ``agent_shield`` SDK if installed -- note it is not published on PyPI and is
     not vendored here, so in every environment we ship, this backend is
     unavailable and (2) is what actually runs. No detection score is quoted for
     it: the only measured backends are the in-repository layers benchmarked in
     ``benchmarks/security/RESULTS.md``. That generated artifact is authoritative;
     do not copy a score into this module docstring where it can drift.
  2. ``builtin_rules`` (the rules bundled with this maverick-shield release)
  3. No-op (only if the user explicitly disabled safety via [safety] profile=off)

Optional balanced/permissive policies allow detector failures with an explicit
scan_error verdict and warning. Strict/required policies block unavailable
checks. Callers can distinguish a clean allow from an unavailable detector.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

from .builtin_rules import RULES, SEVERITY_ORDER
from .builtin_rules import scan as builtin_scan
from .constitutional import parse_rules as _parse_constitution
from .constitutional import scan as _constitutional_scan
from .output_policy import scan_output as output_policy_scan

log = logging.getLogger(__name__)


def _collect_arg_strings(value: Any, keys: bool = True) -> list[str]:
    """Recursively collect every string leaf from a tool-args structure.

    Used so ``scan_tool_call`` can scan the bare argument values (preserving
    their real boundaries) instead of ``repr(args)``, whose quoting can break
    rule anchors. Dict keys are included too, since an injection can hide in a
    key name. With ``keys=False`` only the values are collected, in order.
    """
    out: list[str] = []
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, (bytes, bytearray)):
        # DECODE bytes to their real text -- str(b"rm -rf /") is the repr
        # "b'rm -rf /'", which re-introduces the exact quoting this function
        # exists to strip and lets a destructive command in a bytes arg slip past
        # rule anchors. latin-1 is a lossless byte->char fallback for non-UTF-8.
        raw = bytes(value)
        try:
            out.append(raw.decode("utf-8"))
        except UnicodeDecodeError:
            out.append(raw.decode("latin-1"))
    elif isinstance(value, dict):
        for k, v in value.items():
            if keys and isinstance(k, str):
                out.append(k)
            out.extend(_collect_arg_strings(v, keys))
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            out.extend(_collect_arg_strings(item, keys))
    elif value is not None:
        out.append(str(value))
    return out


try:  # pragma: no cover
    from agent_shield import AgentShield
    _HAVE_SDK = True
except ImportError:
    _HAVE_SDK = False
    AgentShield = None  # type: ignore

# Emit the "SDK not installed" advisory at most once per process (a Shield is
# constructed on every goal run / chat turn, which would otherwise spam it).
_WARNED_SDK_MISSING = False


def _normalize_config_token(value: Any, default: str) -> str:
    """Return a lowercase config token, tolerating hand-edited TOML types."""
    if not value:
        return default
    return str(value).strip().lower() or default


def _decode_disabled() -> bool:
    """Skip decoding hidden layers (``MAVERICK_SHIELD_NO_DECODE``, else
    ``[safety] decode_hidden = false`` when the kernel is installed)."""
    raw = os.environ.get("MAVERICK_SHIELD_NO_DECODE", "").strip().lower()
    if raw:
        return raw in {"1", "true", "yes", "on"}
    try:
        from maverick.config import load_config

        value = ((load_config() or {}).get("safety") or {}).get("decode_hidden")
    except Exception:  # standalone shield or unreadable config: keep decoding
        return False
    return value is False


@dataclass
class ShieldVerdict:
    allowed: bool
    severity: str           # "none" | "low" | "medium" | "high" | "critical"
    reasons: list[str]
    raw: Any = None
    scan_error: bool = False

    @classmethod
    def allow(cls) -> ShieldVerdict:
        return cls(allowed=True, severity="none", reasons=[])

    @classmethod
    def block(cls, severity: str, reason: str, raw: Any = None) -> ShieldVerdict:
        return cls(allowed=False, severity=severity, reasons=[reason], raw=raw)


class Shield:
    """Facade over AgentShield SDK + built-in fallback."""

    BACKEND_SDK = "agent-shield"
    BACKEND_BUILTIN = "builtin"
    BACKEND_NONE = "none"

    def __init__(
        self,
        profile: str = "balanced",
        block_threshold: str | None = None,
        backend: str = "auto",
        warn_if_missing: bool = True,
        scan_input: bool = True,
        scan_tool_calls: bool = True,
        scan_output: bool = True,
        constitution: list | None = None,
        fail_closed: bool = False,
    ):
        # Normalize: profile/threshold/backend come from user-typed TOML, and
        # the comparisons below (== "off"/"none", the {"strict": ...} sensitivity
        # lookup) plus SEVERITY_ORDER are case-sensitive -- a config like
        # profile = "Off" or "Strict" otherwise silently misapplies (safety
        # stays on, or "Strict" falls through to medium sensitivity). Coerce
        # before strip/lower so truthy non-string TOML values (for example
        # profile = true or block_threshold = 1) cannot crash Shield startup.
        profile = _normalize_config_token(profile, "balanced")
        default_threshold = {"strict": "medium", "permissive": "critical"}.get(profile, "high")
        block_threshold = _normalize_config_token(block_threshold, default_threshold)
        backend = _normalize_config_token(backend, "auto")
        self.profile = profile
        self.block_threshold = block_threshold
        self.fail_closed = bool(fail_closed) or profile == "strict"
        # Per-sink enable flags ([safety] scan_input/scan_tool_calls/
        # scan_output). Enforced centrally here so every call site honors the
        # config, so a user who sets scan_tool_calls=false gets that effect at
        # every call site. All default True;
        # disabling a sink is the user's explicit choice on their own instance.
        self._scan_input_enabled = scan_input
        self._scan_tool_calls_enabled = scan_tool_calls
        self._scan_output_enabled = scan_output
        # Operator-defined constitutional rules ([safety] constitution): a
        # customisable regex policy layer checked at input + output. Empty by
        # default, so this is a no-op unless configured.
        self._constitution = _parse_constitution(constitution or [])

        if backend == "none" or profile == "off":
            self.backend = self.BACKEND_NONE
            self._sdk = None
            return

        # Auto: prefer SDK, fall back to builtin.
        if backend in ("auto", "agent-shield") and _HAVE_SDK:
            sens = {"strict": "high", "balanced": "medium", "permissive": "low"}.get(
                profile, "medium"
            )
            try:
                self._sdk = AgentShield(
                    sensitivity=sens, blockOnThreat=True, blockThreshold=block_threshold,
                )
                self.backend = self.BACKEND_SDK
                log.info("Shield: using agent-shield SDK (full ruleset)")
                return
            except Exception as e:
                log.error("Shield: agent-shield SDK init failed (%s); falling back to builtin", e)

        # Built-in fallback
        self._sdk = None
        self.backend = self.BACKEND_BUILTIN
        # A Shield is built once per goal run, so warning every time spams the
        # CLI output (and every `chat` turn). Warn once per process.
        global _WARNED_SDK_MISSING
        if warn_if_missing and not _HAVE_SDK and not _WARNED_SDK_MISSING:
            _WARNED_SDK_MISSING = True
            log.warning(
                "Shield: agent-shield SDK not installed; using built-in rules "
                "(%d bundled patterns). The full SDK is not available from public PyPI",
                len(RULES),
            )

    @property
    def enabled(self) -> bool:
        return self.backend != self.BACKEND_NONE

    @classmethod
    def from_config(cls, *, warn_if_missing: bool = True) -> Shield:
        # ``warn_if_missing`` lets read-only status commands (``maverick
        # version`` / ``doctor``) resolve the backend WITHOUT emitting the
        # "agent-shield SDK not installed" log line -- they already render the
        # shield status in their own formatted output, so the raw warning is
        # redundant and bleeds onto stderr mid-table. Run paths keep the
        # default (warn once per process).
        try:
            from maverick.config import get_safety
            safety = get_safety()
        except Exception:
            safety = {"profile": "balanced", "block_threshold": "high"}
        try:
            from maverick.shield_policy import shield_required
            required = shield_required()
        except ImportError:  # standalone shield package, without the kernel
            required = bool(safety.get("require_shield", False))
        constitution = list(safety.get("constitution") or [])
        try:
            # Signed shared threat rules ([shield] federated_updates), verified
            # again on load. Added to the operator's rules, never replacing them.
            from maverick.shield_updates import load_verified_rules
            constitution += load_verified_rules()
        except ImportError:  # standalone shield package, without the kernel
            pass
        except Exception:  # noqa: BLE001 -- shared rules never stop the shield
            log.warning("shared threat rules could not be loaded", exc_info=True)
        return cls(
            profile=safety.get("profile", "balanced"),
            block_threshold=safety.get("block_threshold"),
            scan_input=safety.get("scan_input", True),
            scan_tool_calls=safety.get("scan_tool_calls", True),
            scan_output=safety.get("scan_output", True),
            constitution=constitution or safety.get("constitution"),
            warn_if_missing=warn_if_missing,
            fail_closed=required,
        )

    def _scan_failure(
        self, detector: str, error: Exception | None = None,
        verdict: ShieldVerdict | None = None,
    ) -> ShieldVerdict:
        """Keep failure evidence through composition, without relaxing a block."""
        log.error("Shield %s unavailable (%s): %s", detector,
                  "blocking" if self.fail_closed else "optional allow", error or "disabled")
        reason = f"shield scan error: {detector} unavailable"
        if verdict is None:
            verdict = ShieldVerdict.allow()
        return ShieldVerdict(
            allowed=verdict.allowed and not self.fail_closed,
            severity=_max_severity(verdict.severity, "high" if self.fail_closed else "none"),
            reasons=[*verdict.reasons, reason], raw=verdict.raw, scan_error=True,
        )

    def _disabled_verdict(self, sink: str) -> ShieldVerdict:
        return self._scan_failure(sink) if self.fail_closed else ShieldVerdict.allow()

    def _scan_via_backend(self, text: str) -> ShieldVerdict:
        # Coerce non-str input to text BEFORE scanning. A bytes / dict / None
        # payload would make the builtin regex `re.search` raise TypeError,
        # which the except-clauses below would swallow into a fail-OPEN allow
        # -- so `scan_input(b"ignore all previous instructions")` would slip a
        # live payload straight through. Decode/stringify so the content is
        # actually inspected.
        if not isinstance(text, str):
            if isinstance(text, (bytes, bytearray)):
                text = bytes(text).decode("utf-8", errors="replace")
            else:
                text = str(text)
        if self.backend == self.BACKEND_NONE:
            return self._disabled_verdict("backend")
        if self.backend == self.BACKEND_SDK:
            try:
                result = self._sdk.scanInput(text)  # type: ignore
                if getattr(result, "blocked", False):
                    threats = getattr(result, "threats", []) or []
                    reasons = [getattr(t, "category", "threat") for t in threats]
                    return ShieldVerdict.block(
                        severity=getattr(result, "severity", "high"),
                        reason="; ".join(reasons) or "blocked",
                        raw=result,
                    )
                verdict = ShieldVerdict.allow()
            except Exception as e:
                verdict = self._scan_failure("SDK", e)
            if not verdict.allowed:
                return verdict
            # An SDK allow (or optional SDK outage) cannot weaken the local
            # floor: literal attacks get this check, not only decoded variants.
            floor = self._scan_builtin_floor(text)
            floor.scan_error = floor.scan_error or verdict.scan_error
            floor.reasons = verdict.reasons + floor.reasons
            return floor
        # builtin
        try:
            blocked, severity, names = builtin_scan(text, block_threshold=self.block_threshold)
            if blocked:
                return ShieldVerdict.block(
                    severity=severity, reason="; ".join(names) or "builtin-rule",
                )
            return ShieldVerdict.allow()
        except Exception as e:
            return self._scan_failure("builtin", e)

    def scan_input(self, text: str) -> ShieldVerdict:
        if not self._scan_input_enabled:
            return self._disabled_verdict("input")
        verdict = self._apply_constitution(text, self._scan_via_backend(text))
        # Decode pre-pass: an attacker hides a payload from the literal
        # detectors with base64 / hex / percent-encoding / Unicode homoglyphs.
        # If the surface form was allowed, re-scan the de-obfuscated variants so
        # an encoded ``rm -rf /`` is caught. Monotonic: only an allowed verdict
        # is ever upgraded to a block, never the reverse. Runs under ANY active
        # backend -- the variant scan goes through the LOCAL builtin floor
        # (``_scan_builtin_floor``), so an SDK deployment also gets decode
        # coverage without per-variant remote calls. Skipping it under the SDK
        # backend would leave every encoding-evasion path uncovered there.
        if verdict.allowed and self.backend != self.BACKEND_NONE:
            decoded = self._scan_decoded_variants(text)
            if decoded is not None:
                decoded.scan_error = decoded.scan_error or verdict.scan_error
                return decoded
        return verdict

    def _scan_builtin_floor(self, text: str) -> ShieldVerdict:
        """Scan ``text`` through the LOCAL builtin regex floor, regardless of the
        active backend. The decode pre-pass uses this so de-obfuscated variants
        are checked even under an SDK backend -- catching an encoded payload the
        SDK only ever saw in obfuscated surface form -- WITHOUT multiplying the
        SDK's (remote) calls by the variant count."""
        if self.backend == self.BACKEND_NONE:
            return ShieldVerdict.allow()
        if not isinstance(text, str):
            text = (bytes(text).decode("utf-8", "replace")
                    if isinstance(text, (bytes, bytearray)) else str(text))
        try:
            blocked, severity, names = builtin_scan(
                text, block_threshold=self.block_threshold)
            if blocked:
                return ShieldVerdict.block(
                    severity=severity, reason="; ".join(names) or "builtin-rule")
            return ShieldVerdict.allow()
        except Exception as e:
            return self._scan_failure("builtin floor", e)

    def _scan_decoded_variants(self, text: str) -> ShieldVerdict | None:
        """Re-scan de-obfuscated variants of an allowed input through the local
        builtin floor; return a BLOCK if any decoded layer trips a rule (the
        payload the literal surface form hid), else ``None``. A pre-pass error
        follows the selected failure policy and retains scan_error. Escape hatch:
        ``MAVERICK_SHIELD_NO_DECODE=1``."""
        if not isinstance(text, str) or _decode_disabled():
            return None
        failure = None
        try:
            from .deobfuscate import decoded_variants
            for variant in decoded_variants(text):
                v = self._apply_constitution(variant, self._scan_builtin_floor(variant))
                if not v.allowed:
                    return ShieldVerdict(
                        allowed=False,
                        severity=v.severity,
                        reasons=["decoded-layer: " + "; ".join(v.reasons)],
                        scan_error=v.scan_error,
                    )
                if v.scan_error:
                    failure = v
        except Exception as e:
            return self._scan_failure("decode pre-pass", e)
        return failure

    def _apply_constitution(self, text: str, verdict: ShieldVerdict) -> ShieldVerdict:
        """Compose operator-defined constitutional rules onto ``verdict``.

        No-op when safety is off, no rules are configured, or the matched
        severity is below the block threshold. Errors follow the selected policy.
        """
        if self.backend == self.BACKEND_NONE or not self._constitution:
            return verdict
        try:
            matched, severity, names = _constitutional_scan(text, self._constitution)
        except Exception as e:
            return self._scan_failure("constitution", e, verdict)
        threshold_idx = SEVERITY_ORDER.get(self.block_threshold, SEVERITY_ORDER["high"])
        if not matched or SEVERITY_ORDER.get(severity, -1) < threshold_idx:
            return verdict
        reasons = [f"constitution: {n}" for n in names]
        if not verdict.allowed:
            return ShieldVerdict(
                allowed=False,
                severity=_max_severity(verdict.severity, severity),
                reasons=verdict.reasons + reasons, scan_error=verdict.scan_error)
        return ShieldVerdict(allowed=False, severity=severity, reasons=reasons,
                             scan_error=verdict.scan_error)

    def scan_tool_call(self, tool_name: str, args: dict) -> ShieldVerdict:
        if not self._scan_tool_calls_enabled:
            return self._disabled_verdict("tool calls")
        # Scan the raw string leaves of ``args`` rather than ``repr(args)``.
        # repr() wraps each value in quotes, so a payload like
        # ``{'cmd': 'rm -rf /'}`` rendered the command as ``'rm -rf /'`` —
        # the closing quote immediately after ``/`` defeated rules whose
        # anchor expects ``/`` to be followed by whitespace/EOL/slash (e.g.
        # ``rm_rf_root``), letting the exact destructive commands the rules
        # target slip through this chokepoint. Joining the bare leaf strings
        # with newlines preserves each value's real boundaries.
        leaves = _collect_arg_strings(args)
        payload = "\n".join([f"tool={tool_name}", *leaves])
        verdict = self._scan_via_backend(payload)
        # Keys sit between the values above, so a command split across fields
        # ({"cmd": "rm", "args": ["-rf", "/"]}) never read as one command. Scan
        # the values alone, in order, as a SECOND scan: appending them to the
        # payload doubled its length and pushed large benign calls over the
        # scan cap (blocked as input_too_large). This text is never longer
        # than the payload above, so it cannot trip the cap on its own.
        values = _collect_arg_strings(args, keys=False)
        if verdict.allowed and values != leaves:
            joined = self._scan_via_backend("\n".join(values))
            if not joined.allowed:
                joined.scan_error = joined.scan_error or verdict.scan_error
                verdict = joined
        # Compose operator-defined constitutional rules onto the tool-call
        # surface too -- the most dangerous sink. scan_input/scan_output do
        # this; omitting it here left the constitution unenforced exactly where
        # it matters most. Error policy is enforced by _apply_constitution.
        verdict = self._apply_constitution(payload, verdict)
        # Decode pre-pass on the tool-call surface: an encoded payload in a
        # tool ARGUMENT must not bypass the detectors either. Same monotonic,
        # local-builtin-floor mechanism as scan_input; runs under any
        # active backend.
        if verdict.allowed and self.backend != self.BACKEND_NONE:
            decoded = self._scan_decoded_variants(payload)
            if decoded is not None:
                decoded.scan_error = decoded.scan_error or verdict.scan_error
                return decoded
        return verdict

    def scan_output(self, text: str, known_prompt: str | None = None) -> ShieldVerdict:
        if not self._scan_output_enabled:
            return self._disabled_verdict("output")
        verdict = self._scan_via_backend(text)
        # Output-side detectors the input rule pack can't see: verbatim
        # system-prompt regurgitation and refusal-then-leak.
        if self.backend == self.BACKEND_NONE:
            return verdict
        threshold_idx = SEVERITY_ORDER.get(self.block_threshold, SEVERITY_ORDER["high"])
        extra_sev = "none"
        extra_reasons: list[str] = []

        # Output-policy detectors: verbatim system-prompt regurgitation,
        # refusal-then-leak. Errors follow the selected policy.
        try:
            policy = output_policy_scan(text, known_prompt=known_prompt)
        except Exception as e:
            verdict = self._scan_failure("output policy", e, verdict)
            policy = None
        if (policy is not None and policy.blocked
                and SEVERITY_ORDER.get(policy.severity, -1) >= threshold_idx):
            extra_sev = _max_severity(extra_sev, policy.severity)
            extra_reasons += policy.reasons

        # Phishing-content detector: credential harvesting + deceptive links,
        # whether the agent fetched the content or is about to emit it.
        try:
            from .phishing import detect_phishing
            ph = detect_phishing(text)
        except Exception as e:
            verdict = self._scan_failure("phishing", e, verdict)
            ph = None
        if (ph is not None and ph.suspicious
                and SEVERITY_ORDER.get(ph.severity, -1) >= threshold_idx):
            extra_sev = _max_severity(extra_sev, ph.severity)
            extra_reasons += [f"phishing: {r}" for r in ph.reasons]

        # Constitutional (operator-defined) rules on the output surface too.
        if self._constitution:
            try:
                c_matched, c_sev, c_names = _constitutional_scan(text, self._constitution)
            except Exception as e:
                verdict = self._scan_failure("constitution", e, verdict)
                c_matched = False
            if c_matched and SEVERITY_ORDER.get(c_sev, -1) >= threshold_idx:
                extra_sev = _max_severity(extra_sev, c_sev)
                extra_reasons += [f"constitution: {n}" for n in c_names]

        if not extra_reasons:
            final = verdict
        elif not verdict.allowed:
            final = ShieldVerdict.block(
                severity=_max_severity(verdict.severity, extra_sev),
                reason="; ".join(verdict.reasons + extra_reasons),
            )
        else:
            final = ShieldVerdict.block(severity=extra_sev, reason="; ".join(extra_reasons))
        final.scan_error = final.scan_error or verdict.scan_error
        # Decode pre-pass on the output surface too: an encoded payload in
        # tool OUTPUT must not bypass the detectors. Same monotonic,
        # local-builtin-floor mechanism as scan_input; runs under any
        # active backend.
        if final.allowed and self.backend != self.BACKEND_NONE:
            decoded = self._scan_decoded_variants(text)
            if decoded is not None:
                decoded.scan_error = decoded.scan_error or final.scan_error
                return decoded
        return final


def _max_severity(a: str, b: str) -> str:
    return a if SEVERITY_ORDER.get(a, -1) >= SEVERITY_ORDER.get(b, -1) else b
