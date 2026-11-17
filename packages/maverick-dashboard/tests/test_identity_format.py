"""Identity/role display formatting for the dashboard UI."""
import pytest
from maverick_dashboard.identity_format import (
    humanize,
    humanize_principal,
    permission_label,
    role_label,
)


def test_google_federated_sub_hides_the_raw_string():
    idn = humanize_principal("user:google-oauth2|100000000000000000001")
    assert idn.name == "Google account"
    assert idn.detail == "…000001"
    assert idn.raw == "user:google-oauth2|100000000000000000001"
    assert idn.kind == "Person"
    # The opaque id never appears in the human label.
    assert "100000000000000000001" not in idn.name


def test_auth0_database_connection_reads_as_email_and_password():
    idn = humanize_principal("user:auth0|000000000000000000000002")
    assert idn.name == "Email & password account"
    assert idn.detail == "…000002"


def test_email_subject_is_shown_directly():
    idn = humanize_principal("user:person@example.com")
    assert idn.name == "person@example.com"
    assert idn.detail == "Email"


def test_unknown_connection_still_avoids_the_raw_sub():
    idn = humanize_principal("user:samlp|00uABCDEF0123456789")
    assert idn.name == "SAML single sign-on account"
    assert "00uABCDEF0123456789" not in idn.name


def test_agent_and_service_principals():
    assert humanize_principal("agent:vega").name == "vega"
    assert humanize_principal("agent:vega").kind == "AI agent"
    assert humanize_principal("service:ci-bot").kind == "Service account"


def test_local_operator_and_empty():
    assert humanize_principal("user:local").name == "Local operator"
    assert humanize_principal("").name == "Unknown"
    assert humanize_principal(None).name == "Unknown"


def test_str_of_identity_is_the_name():
    assert str(humanize_principal("user:google-oauth2|1")) == "Google account"


def test_role_labels_builtin_and_custom():
    assert role_label("admin") == "Administrator"
    assert role_label("operator") == "Operator"
    assert role_label("auditor") == "Auditor"
    assert role_label("viewer") == "Viewer"
    assert role_label("privacy-officer") == "Privacy officer"
    assert role_label("") == ""


def test_permission_labels():
    assert permission_label("operate") == "Run work"
    assert permission_label("audit") == "Review audit trail"
    assert permission_label("admin") == "Administer"
    assert permission_label("view") == "View"


def test_humanize_reads_abbreviations_the_way_people_write_them():
    from maverick_dashboard.identity_format import humanize
    assert humanize("pending_review") == "Pending review"
    assert humanize("ai_act") == "AI act"
    assert humanize("notice_sha256") == "Notice fingerprint"
    assert humanize("gdpr-dsar") == "GDPR DSAR"
    assert humanize("  ") == ""
    assert humanize(None) == ""


@pytest.mark.parametrize("raw,label", [
    ("ec_article_50", "EU AI Act, Article 50"),
    ("eu_ai_act_article_50", "EU AI Act, Article 50"),
    ("ec_gpai_guidelines", "EU guidelines for general-purpose AI models"),
    ("nist_ai_rmf_1_0", "NIST AI RMF 1.0"),
    ("omb_m_25_22", "OMB M-25-22"),
    ("kv_memory", "Saved notes"),
    ("recv_from_agent", "Read messages from other agents"),
    ("send_to_agent", "Send messages to other agents"),
    ("cmmc", "CMMC"),
    ("cmmc_level_2", "CMMC level 2"),
])
def test_humanize_names_regulations_and_tools_from_one_label_table(raw, label):
    # Mangled identifiers ("Ec article 50", "Omb m 25 22", "Kv memory") never
    # reach a customer: whole identifiers map through one label table.
    assert humanize(raw) == label
