"""`maverick migrate` must not lint REAL config sections as unread.

The fast wizard writes [capabilities] and
[security], the advanced wizard writes [models] -- and `maverick migrate`
told the user all three "are not sections the runtime reads; silently does
nothing." Acting on that advice would delete live configuration (the whole
self-hosted setup runs through [models]). KNOWN_SECTIONS held 44 names while
the runtime reads ~90; this pins the wizard-written and kernel-core ones.
"""
from __future__ import annotations

from maverick.migrate import KNOWN_SECTIONS

# Sections the installer wizard itself writes into config.toml.
_WIZARD_WRITTEN = {"providers", "budget", "safety", "sandbox", "capabilities",
                   "security", "models", "channels"}

# Core kernel readers verified in source (config.py get_* helpers and
# load_config().get("<section>") call sites).
_KERNEL_READ = {"features", "persona", "autonomy", "calibration", "credit",
                "adaptive_compute", "search", "skill_synthesis", "experience",
                "durable", "egress", "quotas", "mcp_servers", "memory",
                "encryption", "tenancy", "verification", "voice", "privacy"}


def test_wizard_written_sections_are_known():
    missing = _WIZARD_WRITTEN - KNOWN_SECTIONS
    assert not missing, (
        f"migrate would tell users these wizard-written sections do nothing: "
        f"{sorted(missing)}"
    )


def test_kernel_read_sections_are_known():
    missing = _KERNEL_READ - KNOWN_SECTIONS
    assert not missing, sorted(missing)


def test_runtime_sections_are_known():
    """The learning-engine sections the runtime reads (config.py get_* helpers)
    and the wizard writes -- enabling them must not make `maverick migrate` claim
    they 'do nothing', which would lead a user to delete a live feature."""
    runtime_sections = {"data_engine", "consequence", "emergent_protocol",
               "emergent_codec", "operations_scientist"}
    missing = runtime_sections - KNOWN_SECTIONS
    assert not missing, f"runtime reads these but migrate would flag them: {sorted(missing)}"


def test_runtime_section_config_lints_clean():
    from maverick.migrate import _lint_unknown_sections
    cfg = {s: {"enable": True} for s in
           ("data_engine", "consequence", "emergent_protocol",
            "emergent_codec", "operations_scientist")}
    findings = [f for f in _lint_unknown_sections(cfg)
                if "not a section the runtime reads" in f.message]
    assert not findings, [f.id for f in findings]


def test_wizard_fast_config_lints_clean(tmp_path):
    """The exact section set `maverick init --fast` writes must produce no
    'is not a section the runtime reads' lint findings."""
    from maverick.migrate import migrate
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        "\n".join([
            "[providers.anthropic]", 'api_key = "${ANTHROPIC_API_KEY}"',
            "[budget]", "max_dollars = 5.0",
            "[safety]", 'profile = "balanced"',
            "[sandbox]", 'backend = "local"',
            "[capabilities]", "computer_use = false",
            "[security]", 'denied_tools = ["shell"]',
            "[models]", 'orchestrator = "vllm:stub-1"',
        ]) + "\n",
        encoding="utf-8",
    )
    report = migrate(cfg, apply=False)
    unread = [f for f in report.findings
              if "not a section the runtime reads" in f.message]
    assert not unread, [f.message for f in unread]
