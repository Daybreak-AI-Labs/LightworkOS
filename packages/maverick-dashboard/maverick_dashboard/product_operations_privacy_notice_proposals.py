"""Copilot opens the same protected native notice proposal form."""
from . import privacy_notice_proposals as service
from .product_operations import Adapter, EmptyInput, Preview, Snapshot


def snapshot(request, _selection):
    service.authority(request, write=True)
    state = service.catalog(request)
    missing = [label for key, label in (("notices", "a retained current notice"), ("references", "a current document from an independently approved research source"), ("publications", "a current consent publication")) if not state[key]]
    return Snapshot(state["revision"], "Current native notice and approved research-source metadata",
        "Choose current named records and your local files in the protected form, review their recorded fingerprints, then save a proposal for independent review. No files are retained, no legal applicability is inferred and nothing is published.",
        details={"privacy_notice_proposal_form": {"context": state["context"]}},
        blocked="First add " + ", ".join(missing) + " using the ordinary Privacy and Consent controls." if missing else "")


def prepare(request, selection, _arguments):
    value = snapshot(request, selection)
    return Preview(value.summary, native=value.details)


def entries():
    return (Adapter("privacy.notice.proposal.create", "Propose a privacy notice update", "reviews", service.PAGE,
        (service.PAGE, "/privacy", "/privacy/regulatory-intelligence"), EmptyInput, snapshot, prepare,
        aliases=("suggest privacy notice changes", "create a notice update", "propose a privacy notice change")),)
