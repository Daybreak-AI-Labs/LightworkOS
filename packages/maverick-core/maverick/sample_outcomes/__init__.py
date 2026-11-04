"""Department-picked first outcomes on bundled synthetic sample data.

A new user picks a department and gets ONE concrete first task that runs an
existing specialist pack against small, clearly synthetic files (the sample
company "Northwind Fixtures") inside a sample workspace. The sample workspace
is a folder under the configured sandbox workdir, so the pack's ``read_file``
tool can read the files with a relative path, from the CLI and from the
dashboard alike. Everything the run produces is marked as sample data and
never counts as real evidence: the workspace carries a marker file, the goal
title carries :data:`SAMPLE_TITLE_PREFIX`, the goal description repeats the
rule, and a ``sample_data`` goal event is recorded.
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

SAMPLE_TITLE_PREFIX = "Sample: "
SAMPLE_WORKSPACE_DIRNAME = "sample-outcomes"
SAMPLE_MARKER_FILENAME = "SAMPLE_DATA.md"
SAMPLE_EVENT_KIND = "sample_data"
SAMPLE_RULE = ("This task runs on bundled sample data. Everything it produces "
               "is marked as sample data and never counts as real evidence.")
DEFAULT_DEPARTMENT = "finance"

_FIXTURES_ROOT = Path(__file__).resolve().parent


@dataclass(frozen=True)
class FirstOutcome:
    department: str      # slug; also the fixture folder name
    label: str           # what the user picks
    pack: str            # the specialist pack (maverick/domains/<pack>.toml)
    goal: str            # the goal a business user would write
    gate: str            # "approval" or "review", as the pack's output contract says
    files: tuple[str, ...]

    @property
    def lands_in(self) -> str:
        """Where the reviewed result waits for a person."""
        return "Approvals" if self.gate == "approval" else "Results"

    @property
    def title(self) -> str:
        return SAMPLE_TITLE_PREFIX + self.goal


# Every sample's pack must start on a fresh install. The kernel refuses a
# specialist whose workflow needs a tool the install lacks, so these are packs
# that read workspace files themselves; packs that read live systems (an
# accounts-payable connector, web search) stay for real work. Guarded by
# test_every_offered_sample_specialist_can_start_on_a_fresh_install.
FIRST_OUTCOMES: dict[str, FirstOutcome] = {o.department: o for o in (
    FirstOutcome("finance", "Finance", "proc_p2p_exceptions",
        "Match this month's invoices to purchase orders and receipts, and list every exception before anything is paid.",
        "review", ("invoices.csv", "purchase_orders.csv", "receipts.csv", "vendor_master.csv")),
    FirstOutcome("privacy", "Privacy & compliance", "data_pii_scan",
        "Work out which systems hold this customer's data and what we must tell them to answer their rights request.",
        "review", ("data_map.csv", "rights_request.md")),
    FirstOutcome("security", "Security", "itgrc_incident_response",
        "Check these reported emails, tell me which ones are phishing and who needs warning, and propose containment steps.",
        "approval", ("mailbox_export.csv", "known_senders.md")),
    FirstOutcome("legal", "Legal", "legal_nda_desk",
        "Review these three NDAs against our playbook and tell me which ones counsel needs to look at and why.",
        "review", ("nda_playbook.md", "nda_a_harbor_supply.md", "nda_b_pinecrest_labs.md", "nda_c_summit_retail.md")),
    FirstOutcome("hr", "HR", "hr_onboarding",
        "Build the day-one plan for our new warehouse coordinator from the hire record and the provisioning checklist.",
        "review", ("new_hire.md", "provisioning_checklist.md")),
    FirstOutcome("procurement", "Procurement", "proc_po_chaser",
        "Which open purchase orders are overdue, which ones put us closest to a stockout, and who should chase them?",
        "review", ("open_purchase_orders.csv", "supplier_contacts.csv")),
    FirstOutcome("customer_support", "Customer support", "cx_ticket_insights",
        "Tell me what is driving this month's support tickets, which ones are still open, and where we need more coverage.",
        "review", ("tickets.csv",)),
    FirstOutcome("tax", "Tax", "tax_irs_notice",
        "Read this tax notice, tie the proposed adjustment to our workpapers, and draft a response for the preparer.",
        "review", ("notice_letter.md", "workpaper_summary.md")),
)}


def departments() -> list[dict[str, str]]:
    """The eight choices, in display order, as plain dicts for menus and JSON."""
    return [{"department": o.department, "label": o.label, "pack": o.pack, "goal": o.goal,
             "gate": o.gate, "lands_in": o.lands_in} for o in FIRST_OUTCOMES.values()]


def resolve_department(value: str | None, default: str | None = DEFAULT_DEPARTMENT) -> str | None:
    """Map a menu answer or slug to a department slug; ``default`` when unknown."""
    text = (value or "").strip().lower()
    if not text:
        return default
    for outcome in FIRST_OUTCOMES.values():
        if text == outcome.department or text == outcome.label.lower():
            return outcome.department
    for outcome in FIRST_OUTCOMES.values():
        if text.startswith(outcome.label.lower()) or text.split()[0] == outcome.department:
            return outcome.department
    return default


def get(department: str) -> FirstOutcome:
    try:
        return FIRST_OUTCOMES[department]
    except KeyError:
        raise ValueError(f"unknown department: {department!r}") from None


def fixture_dir(department: str) -> Path:
    return _FIXTURES_ROOT / get(department).department


def load_fixtures(department: str) -> dict[str, str]:
    """Every bundled file for the department, including its README, as text."""
    folder = fixture_dir(department)
    return {p.name: p.read_text(encoding="utf-8") for p in sorted(folder.iterdir()) if p.is_file()}


def expected_result(department: str) -> str:
    """The README paragraph that says what a correct result contains."""
    return load_fixtures(department)["README.md"]


def sandbox_workdir(workdir: str | Path | None = None) -> Path:
    if workdir is None:
        from ..config import get_sandbox

        workdir = get_sandbox()["workdir"]
    return Path(workdir).expanduser()


def relative_paths(department: str) -> list[str]:
    """Paths the pack's ``read_file`` tool uses (relative to the sandbox workdir)."""
    outcome = get(department)
    return [f"{SAMPLE_WORKSPACE_DIRNAME}/{outcome.department}/{name}" for name in outcome.files]


def sample_workspace_path(department: str, workdir: str | Path | None = None) -> Path:
    return sandbox_workdir(workdir) / SAMPLE_WORKSPACE_DIRNAME / get(department).department


def is_sample_workspace(path: str | Path) -> bool:
    return (Path(path) / SAMPLE_MARKER_FILENAME).is_file()


def create_sample_workspace(department: str, workdir: str | Path | None = None) -> Path:
    """Copy the department's fixtures into the sample workspace and mark it.

    Idempotent: re-running refreshes the files from the bundled copies.
    """
    outcome = get(department)
    target = sample_workspace_path(department, workdir)
    target.mkdir(parents=True, exist_ok=True)
    source = fixture_dir(department)
    for name in (*outcome.files, "README.md"):
        shutil.copyfile(source / name, target / name)
    (target / SAMPLE_MARKER_FILENAME).write_text(
        "# Sample data\n\n"
        f"This folder was created by Lightwork for the {outcome.label} first outcome. "
        f"{SAMPLE_RULE}\n\nPack: {outcome.pack}\nFiles: {', '.join(outcome.files)}\n",
        encoding="utf-8",
    )
    return target


def goal_description(department: str) -> str:
    """The brief a run gets: which files to read, what to hand back, the sample rule."""
    outcome = get(department)
    files = "\n".join(f"- {path}" for path in relative_paths(department))
    return (
        f"{SAMPLE_RULE}\n\n"
        f"Read these files from the workspace with read_file (the paths are relative to the workspace):\n{files}\n"
        f"- {SAMPLE_WORKSPACE_DIRNAME}/{outcome.department}/README.md describes the data.\n\n"
        f"Hand the result to a person: it waits in {outcome.lands_in} and nothing is sent, "
        "paid, provisioned or changed without their sign-off."
    )


def cli_command(department: str) -> str:
    """The one-line command printed at the end of setup: the same brief,
    sample files and sample record as the dashboard's first outcome. No model
    flag: the pack and the configured role models decide the model."""
    return f"maverick start --sample {get(department).department}"


def mark_goal_as_sample(world, goal_id: int, department: str) -> int:
    """Record on the goal itself that it ran on sample data."""
    outcome = get(department)
    return world.append_event(goal_id, "system", SAMPLE_EVENT_KIND,
                              f"{SAMPLE_RULE} Department: {outcome.label}. Pack: {outcome.pack}.")


def is_sample_goal(world, goal) -> bool:
    title = str(getattr(goal, "title", "") or "")
    if title.startswith(SAMPLE_TITLE_PREFIX):
        return True
    try:
        return any(e.kind == SAMPLE_EVENT_KIND for e in world.goal_events(goal.id, limit=50))
    except Exception:
        return False


__all__ = [
    "DEFAULT_DEPARTMENT", "FIRST_OUTCOMES", "FirstOutcome", "SAMPLE_EVENT_KIND", "SAMPLE_MARKER_FILENAME",
    "SAMPLE_RULE", "SAMPLE_TITLE_PREFIX", "SAMPLE_WORKSPACE_DIRNAME", "cli_command", "create_sample_workspace",
    "departments", "expected_result", "fixture_dir", "get", "goal_description", "is_sample_goal",
    "is_sample_workspace", "load_fixtures", "mark_goal_as_sample", "relative_paths", "resolve_department",
    "sample_workspace_path", "sandbox_workdir",
]
