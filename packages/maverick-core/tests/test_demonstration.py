"""Tests for programming-by-demonstration (maverick.demonstration).

Induction routes through intake.generate_profile -> validate_profile, so a
demonstrated pack inherits the same envelope clamp as a described one. The
deterministic path needs no LLM; the LLM path is exercised with a fake.
"""
from __future__ import annotations

from maverick import demonstration as demo
from maverick.demonstration import Demonstration, DemoStep


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------
def test_parse_prefixed_text():
    text = (
        "ACTION[web_search]: look up the vendor's filings -> sec.gov\n"
        "SEE: the latest 10-K is from 2025\n"
        "NOTE: we only care about going-concern language\n"
        "draft the risk summary\n"
    )
    steps = demo.parse_demonstration(text)
    kinds = [(s.kind, s.tool) for s in steps]
    assert kinds == [
        ("action", "web_search"),
        ("observation", ""),
        ("narration", ""),
        ("action", ""),   # bare line -> action
    ]
    assert steps[0].target == "sec.gov"


def test_parse_jsonl_lines():
    text = (
        '{"kind": "action", "summary": "pull invoices", "tool": "sql_query"}\n'
        '{"summary": "match to POs"}\n'   # missing kind -> action
        "not json, treated as action\n"
    )
    steps = demo.parse_demonstration(text)
    assert [s.kind for s in steps] == ["action", "action", "action"]
    assert steps[0].tool == "sql_query"


def test_parse_skips_blank_and_comment_lines():
    steps = demo.parse_demonstration("# a comment\n\n   \nACTION: real step\n")
    assert len(steps) == 1 and steps[0].summary == "real step"


def test_load_demonstration_titles_from_stem(tmp_path):
    f = tmp_path / "weekly_close.txt"
    f.write_text("ACTION[read_file]: open the trial balance\nNOTE: tie out cash\n")
    d = demo.load_demonstration(f)
    assert d.title == "weekly close"
    assert d.observed_tools() == ["read_file"]
    assert "tie out cash" in d.narration()


# --------------------------------------------------------------------------
# induction (deterministic)
# --------------------------------------------------------------------------
def _demo() -> Demonstration:
    return Demonstration(
        title="vendor invoice reconciliation",
        steps=[
            DemoStep("action", "Pull open invoices from the ledger", tool="read_file"),
            DemoStep("observation", "Some invoices lack a PO"),
            DemoStep("action", "Three-way match invoice to PO and receipt", tool="web_search"),
            DemoStep("narration", "We escalate any mismatch over $500"),
        ],
    )


def test_induce_deterministic_builds_workflow_and_tools():
    profile = demo.induce_profile(_demo(), llm=None)
    # Workflow mirrors the non-narration steps + an appended review gate.
    names = [s.name for s in profile.workflow]
    assert names[-1] == "Route for review"
    assert profile.workflow[-1].gate == "review"
    assert any("Pull open invoices" in n for n in names)
    # Observed tools survive the intake clamp (both are low/medium-risk reads).
    assert "read_file" in profile.allow_tools
    assert "web_search" in profile.allow_tools
    assert profile.authoring == "generated"
    assert "recorded demonstration" in profile.description


def test_induce_clamps_high_risk_tools():
    d = Demonstration(
        title="risky task",
        steps=[DemoStep("action", "delete the temp files", tool="shell")],
    )
    profile = demo.induce_profile(d, llm=None)
    # shell is in the generated deny floor -> stripped from the envelope.
    assert "shell" not in profile.allow_tools
    assert "shell" in profile.deny_tools


def test_induce_empty_demo_still_safe():
    profile = demo.induce_profile(Demonstration(title="empty task", steps=[]), llm=None)
    # A demo with no steps still yields a valid, clamped pack with a review gate.
    assert profile.name == "empty_task"
    assert profile.workflow and profile.workflow[-1].gate == "review"


# --------------------------------------------------------------------------
# induction (LLM path)
# --------------------------------------------------------------------------
class _FakeResp:
    def __init__(self, text):
        self.text = text


class _FakeLLM:
    def __init__(self, text):
        self._text = text
        self.calls = []

    def complete(self, *, system, messages, model=None, budget=None, max_tokens=0):
        self.calls.append(messages[0]["content"])
        return _FakeResp(self._text)


def test_induce_llm_path_uses_proposal():
    llm = _FakeLLM('{"persona": "You reconcile invoices.", '
                   '"description": "Invoice recon specialist", '
                   '"allow_tools": ["read_file"], "max_risk": "low"}')
    profile = demo.induce_profile(_demo(), llm=llm)
    assert "reconcile invoices" in profile.persona.lower()
    assert profile.allow_tools == ["read_file"]
    # The transcript was actually rendered into the prompt.
    assert "vendor invoice reconciliation" in llm.calls[0]


def test_induce_llm_failure_falls_back_safely():
    class _BoomLLM:
        def complete(self, **_kw):
            raise RuntimeError("provider down")

    # generate_profile swallows a proposer exception -> safe default + clamp.
    profile = demo.induce_profile(_demo(), llm=_BoomLLM())
    assert profile.name == "vendor_invoice_reconciliation"
    assert profile.workflow  # default workflow present


# --------------------------------------------------------------------------
# redaction
# --------------------------------------------------------------------------
def test_demo_step_redacts_secrets():
    s = DemoStep("action", "export AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE12345").normalized()
    assert "AKIAIOSFODNN7EXAMPLE12345" not in s.summary


def test_induce_redacts_secret_in_raw_demostep():
    # A Demonstration built programmatically carries RAW DemoSteps (only
    # parse_demonstration normalizes). induce_profile must redact every field
    # that reaches the persisted pack -- summary, target, narration, AND title
    # (which becomes the name + provenance note) -- not just the ones the
    # deterministic proposer happens to touch. Use a detector-recognized token.
    secret = "ghp_" + "A" * 36
    raw = Demonstration(title=f"deploy with {secret}", steps=[
        DemoStep("action", f"run {secret}", tool="read_file", target=f"repo {secret}"),
        DemoStep("narration", f"the pat is {secret}"),
    ])
    p = demo.induce_profile(raw, llm=None)
    blob = " ".join([p.name, p.description, *[w.name + " " + w.instruction for w in p.workflow]])
    assert secret not in blob


def test_parse_bounds_steps_and_redact_window():
    # An attacker-supplied capture log must not drive unbounded work: the step
    # count is capped, and redaction runs over a bounded window (so a multi-MB
    # paste is cheap) -- while a secret inside the kept region is still redacted.
    many = "\n".join(f"ACTION: step {i}" for i in range(50_000))
    steps = demo.parse_demonstration(many)
    assert len(steps) <= demo._MAX_DEMO_STEPS

    secret = "ghp_" + "Z" * 36
    huge = "b" * 5000 + " " + secret          # secret beyond the kept window
    cleaned = demo._clean(huge)
    assert len(cleaned) <= demo._MAX_STEP_CHARS and secret not in cleaned
    near = "a" * 380 + " " + secret + " tail"  # secret inside the window
    assert secret not in demo._clean(near)


def test_load_demonstration_bounds_file_read(tmp_path):
    f = tmp_path / "big.txt"
    f.write_text("ACTION: ok\nACTION: " + "y" * (demo._MAX_DEMO_BYTES + 1000) + "\n")
    d = demo.load_demonstration(f)
    # The oversized second line is truncated by the byte cap, not loaded whole.
    assert all(len(s.summary) <= demo._MAX_STEP_CHARS for s in d.steps)


def test_induce_caps_allow_tools_from_pathological_demo():
    # Thousands of distinct tool hints must not synthesize an unbounded envelope
    # (validate_profile clamps by risk, not by count).
    d = Demonstration(title="firehose", steps=[
        DemoStep("action", f"step {i}", tool=f"tool_{i}") for i in range(5000)
    ])
    p = demo.induce_profile(d, llm=None)
    assert len(p.allow_tools) <= demo._MAX_OBSERVED_TOOLS
