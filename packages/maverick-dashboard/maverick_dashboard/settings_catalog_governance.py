"""All-settings catalog rows for the governance group.

Kept apart from settings_catalog.py so each group can be extended without
editing the shared catalog. entries receives the catalog's own row and
column types (a plain import would be circular).

These rows cover the detailed settings of the AI governance, risk and vendor
modules: evidence analysis and the programs that open files from outside,
the AI evidence records, identity governance connectors and their schedules,
third-party management, tech-risk compliance, governance agents, red-team
testing, cloud AI agent oversight, AI cost collection, media provenance, the
document vault and incident attachments. Every bound mirrors the reader that
uses the key, so a value the page accepts is one the module accepts.
Combinations the kernel rejects (a file reader without the isolated area or
its file kinds, a retry ceiling below its first wait, a lookback longer than a
collection may cover, the Databricks check without cloud oversight) are
refused by :func:`cross_checks`, so a saved setup never switches itself off.

Pinned fingerprints are never typed: the page works them out from an
uploaded file, or from the files installed on this server.

Not here, with the reason:

* ``tech_risk_compliance.continuous_evidence.stock_collectors.sources``: see
  the guided source form on Continuous evidence. It stores each exact source
  in that workspace's signed definition, with separate approval and enrollment.
  ``grc_sync.response_field_params`` is in settings_catalog_structured as a
  table of names and values.
* ``red_team_assurance.commitment_secret_ref`` and the connectors'
  ``credential_secret_ref`` keys name environment variables on the server;
  the sealed key rows below make the key itself adjustable instead.
"""
from __future__ import annotations

_G = "AI governance"

# Server file locations: absolute, no "." or ".." steps, no control characters.
_SEG = r"(?!\.{1,2}(?:/|\Z))[^/\x00-\x1f\x7f]{1,255}"
_PATH = rf"/{_SEG}(?:/{_SEG})*"
_OPT_PATH = rf"({_PATH})?"
_TRAINEDDATA = rf"(/(?:{_SEG}/)*eng\.traineddata)?"
_FINGERPRINT = r"([0-9a-f]{64})?"
_VERSION = r"([A-Za-z0-9][A-Za-z0-9.+_-]{0,63})?"
# A public server name: letters in the last part (so never a bare IP
# address) and never a name that only works inside a private network. The
# connection itself is checked again when it is made.
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_PRIVATE_NAMES = r"(?:localhost|local|localdomain|internal|intranet|lan|home|corp|private)"
_PUBLIC_HOST = (
    rf"(?=.{{1,253}}\Z)(?!(?:.*\.)?{_PRIVATE_NAMES}\Z)(?:{_LABEL}\.)+[a-z]{{2,63}}"
)
_OPT_HOST = rf"({_PUBLIC_HOST})?"
_HOST_CI = (
    rf"(?i:(?!(?:[a-z0-9-]+\.)*{_PRIVATE_NAMES}(?:[:/]|\Z))(?:{_LABEL}\.)+[a-z]{{2,63}})"
)
_PORT = r"(?::[0-9]{1,5})?"
_SERVICENOW_URL = rf"(https://{_HOST_CI}{_PORT}/?)?"
_ARCHER_URL = (
    rf"(https://{_HOST_CI}{_PORT}(?:/(?i:rsaarcher|archer)(?:/(?i:api|platformapi))?)?/?)?"
)
_OKTA_URL = (
    rf"(https://(?i:(?:{_LABEL}\.)+(?:okta|okta-emea|oktapreview)\.com)(?::443)?/?)?"
)
_PURVIEW_URL = rf"(https://(?i:(?:{_LABEL}\.)+purview\.azure\.(?:com|us))(?::443)?/?)?"
_ORG_ID = r"[^\s<>\"'{}]{0,256}"

_EVIDENCE_MEDIA = (
    ("pdf", "PDF documents"), ("jpeg", "JPEG pictures"), ("png", "PNG pictures"),
    ("xlsx", "Excel workbooks"), ("xls", "Older Excel workbooks"),
    ("text", "Plain text files"),
)
_DOCUMENT_MEDIA = (
    ("application/json", "Structured data files"),
    ("application/pdf", "PDF documents"),
    ("application/vnd.openxmlformats-officedocument.presentationml.presentation",
     "PowerPoint presentations"),
    ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "Excel workbooks"),
    ("application/vnd.openxmlformats-officedocument.wordprocessingml.document",
     "Word documents"),
    ("image/jpeg", "JPEG pictures"), ("image/png", "PNG pictures"),
    ("image/webp", "WebP pictures"), ("text/csv", "Comma-separated text files"),
    ("text/plain", "Plain text files"),
)
_ALL_DOCUMENT_MEDIA = [value for value, _label in _DOCUMENT_MEDIA]
_COLLECTORS = (
    ("local_soc2_v1", "Built-in SOC 2 checks on this server"),
    ("aws_config_posture_v1", "AWS Config"),
    ("aws_security_hub_v1", "AWS Security Hub"),
    ("azure_defender_v1", "Microsoft Defender for Cloud"),
    ("azure_policy_posture_v1", "Azure Policy"),
    ("gcp_security_command_center_v1", "Google Security Command Center"),
    ("github_security_v1", "GitHub security"),
    ("okta_posture_v1", "Okta security settings"),
)
_RATING_PROVIDERS = (
    ("riskrecon", "RiskRecon"), ("securityscorecard", "SecurityScorecard"),
    ("hacknotice", "HackNotice"), ("supplywisdom", "SupplyWisdom"),
    ("iss_corporate_solutions", "ISS Corporate Solutions"),
    ("generic_approved", "Another approved provider"),
)
_IDENTITY_PROVIDERS = (("entra", "Microsoft Entra"), ("okta", "Okta"),
                       ("purview", "Microsoft Purview"))
_ENTRA_CLOUDS = (
    ("https://graph.microsoft.com", "Worldwide"),
    ("https://graph.microsoft.us", "United States government"),
    ("https://dod-graph.microsoft.us", "United States defense"),
    ("https://microsoftgraph.chinacloudapi.cn", "China"),
)
_GRC_TARGETS = (("servicenow_irm", "ServiceNow risk management", _SERVICENOW_URL,
                 "https://yourcompany.service-now.com"),
                ("archer", "Archer", _ARCHER_URL, "https://archer.yourcompany.com"))

_EA = "maverick_dashboard.ai_evidence_analysis_composition"
_BIGGER_FILES = ("Bigger or more complex files from outside will be opened, which gives a "
                 "harmful file more room.")
_LONGER_RUNS = "A harmful file from outside will be able to keep the reader busy for longer."
_MORE_MEMORY = "The reader will be able to use more of this server's memory on a harmful file."
_MORE_TEXT = "More text from each file from outside will be kept and passed on."


def entries(S, C, Column) -> tuple:  # noqa: ARG001 -- filled by the group
    return (
        *_evidence_analysis(S),
        *_file_readers(S),
        *_evidence_records(S),
        *_identity_connectors(S),
        *_identity_controls(S),
        *_third_party(S),
        *_tech_risk(S),
        *_governance_modules(S),
        *_outbound_vendors(S),
        S("swarm", "finding_post_max_chars", "Length of helper findings shared with the team",
          "How much of each helper agent's final answer is posted for the other helpers to "
          "read. The full answer still reaches the lead agent and the task record.", "number",
          "Spending & limits", 1500, "maverick.agent", minimum=200, maximum=100000,
          integer=True, unit="characters", env=("MAVERICK_FINDING_POST_MAX_CHARS",)),
    )


# ------------------------------------------------------------ evidence analysis
def _evidence_analysis(S) -> tuple:
    sub = {"subgroup": "Evidence analysis"}
    return (
        S("ai_evidence_analysis", "enabled_media_types", "Kinds of files evidence analysis opens",
          "Only these kinds of files are accepted as evidence. Choose at least one while "
          "evidence analysis is on. Older Excel workbooks also need older Excel reading "
          "turned on below.", "multiselect", _G, [], _EA, choices=_EVIDENCE_MEDIA,
          weaker="grow", aliases="evidence media types file formats",
          warning="More kinds of files from outside will be opened and read on this server.",
          **sub),
        S("ai_evidence_analysis", "max_artifact_bytes", "Largest evidence file",
          "Bigger files are refused before they are opened.", "number", _G, 52428800, _EA,
          minimum=1, maximum=100, integer=True, scale=1048576, unit="MB", weaker="higher",
          warning="Larger files from outside will be opened, which gives a harmful file "
                  "more room.", **sub),
        S("ai_evidence_analysis", "max_artifacts_per_case", "Files per evidence case",
          "The most files one case may hold.", "number", _G, 20, _EA, minimum=1,
          maximum=100, integer=True, unit="files", weaker="higher",
          warning="More files from outside can be added to one case.", **sub),
        S("ai_evidence_analysis", "max_extracted_text_bytes", "Text kept from each file",
          "The most text read out of one file and passed on for analysis.", "number", _G,
          1048576, _EA, minimum=1, maximum=10240, integer=True, scale=1024, unit="KB",
          weaker="higher",
          warning="More text from each outside file will be kept and passed on.", **sub),
        S("ai_evidence_analysis", "max_authority_records", "Evidence approval records kept",
          "The most records of approved files, reviewers and checks kept. Expired ones are "
          "compacted first.", "number", _G, 100000, _EA, minimum=4, maximum=1000000,
          integer=True, unit="records", **sub),
        S("ai_evidence_analysis", "retention_seconds", "Keep evidence analysis records for",
          "How long analysis results and their history are kept.", "number", _G, 31536000,
          _EA, minimum=1, maximum=3650, integer=True, scale=86400, unit="days",
          weaker="lower", warning="Evidence analysis records will be deleted sooner.", **sub),
    )


def _limit(S, section, key, label, help_text, default, sub, warning=_BIGGER_FILES, **bounds):
    """A limit on a program that opens files from outside: raising it is confirmed."""
    return S(section, key, label, help_text, "number", _G, default, _EA, integer=True,
             weaker="higher", warning=warning, **sub, **bounds)


def _pin(S, section, key, label, help_text, what, sub, pattern=_FINGERPRINT, **extra):
    """A pinned program location, version or fingerprint: any change is confirmed.

    A fingerprint is never typed: the page works it out from an uploaded file
    (or, with ``fingerprint_of``, from the files installed on this server)."""
    if pattern == _FINGERPRINT:
        return S(section, key, label, help_text, "fingerprint", _G, "", _EA,
                 weaker="change", warning=f"A different {what} will be trusted to open "
                                          "files from outside.", **sub, **extra)
    return S(section, key, label, help_text, "text", _G, "", _EA, pattern=pattern,
             weaker="change", warning=f"A different {what} will be trusted to open files "
                                      "from outside.", **sub, **extra)


def _file_readers(S) -> tuple:
    box = {"subgroup": "Evidence analysis: isolated file reading"}
    pic = {"subgroup": "Evidence analysis: reading text in pictures"}
    xls = {"subgroup": "Evidence analysis: older Excel files"}
    sandbox = "ai_evidence_analysis.parser_sandbox"
    ocr = "ai_evidence_analysis.ocr"
    old = "ai_evidence_analysis.legacy_xls"
    fp_help = ("Upload the same file that is on the server and Lightwork works out its "
               "fingerprint. Files are not opened if the file on the server does not match.")
    installed = ("Lightwork works it out from the files installed on this server. Files are "
                 "not opened if those files change later.")
    return (
        S(sandbox, "enable", "Open files in an isolated area",
          "Picture reading and older Excel reading run in a locked-down area on this server "
          "with no network access. It must be on while either of them is on, and off when "
          "both are off.", "toggle", _G, False, _EA, weaker=False,
          warning="Files from outside will no longer be opened in the isolated area. Picture "
                  "and older Excel reading stop until it is turned back on.", **box),
        S(sandbox, "mode", "Kind of isolation",
          "The kind of isolation program used to open files. Choose it before turning "
          "isolated file reading on.", "select", _G, "", _EA,
          choices=(("", "Not chosen"), ("bubblewrap", "Bubblewrap (the only kind supported)")),
          **box),
        _pin(S, sandbox, "launcher", "Isolation program on this server",
             "The full location of the isolation program, such as /usr/bin/bwrap.",
             "isolation program", box, pattern=_OPT_PATH, max_length=1024),
        _pin(S, sandbox, "launcher_sha256", "Isolation program fingerprint", fp_help,
             "isolation program", box),
        _pin(S, sandbox, "launcher_version", "Isolation program version",
             "The exact version of the isolation program, such as 0.8.0.",
             "isolation program", box, pattern=_VERSION, max_length=64),

        S(ocr, "enable", "Read text in pictures",
          "A text-recognition program on this server reads the words in pictures sent as "
          "evidence. Needs isolated file reading on and JPEG or PNG pictures allowed above.",
          "toggle", _G, False, _EA, weaker=True,
          warning="Pictures from outside will be opened by one more program on this server. "
                  "It runs isolated, but it is one more program a harmful file can target.",
          **pic),
        _pin(S, ocr, "executable", "Text-recognition program on this server",
             "The full location of the text-recognition program, such as /usr/bin/tesseract.",
             "text-recognition program", pic, pattern=_OPT_PATH, max_length=1024),
        _pin(S, ocr, "executable_sha256", "Text-recognition program fingerprint", fp_help,
             "text-recognition program", pic),
        _pin(S, ocr, "tesseract_version", "Text-recognition program version",
             "The exact version of the text-recognition program, such as 5.3.0.",
             "text-recognition program", pic, pattern=_VERSION, max_length=64),
        _pin(S, ocr, "traineddata_path", "English language file on this server",
             "The full location of the English language file the program uses. Its name "
             "ends in eng.traineddata.", "language file", pic, pattern=_TRAINEDDATA,
             max_length=1024),
        _pin(S, ocr, "traineddata_sha256", "English language file fingerprint", fp_help,
             "language file", pic),
        S(ocr, "runtime_library_paths", "Program libraries on this server",
          "The full locations of the library files the text-recognition program loads. "
          "Their combined fingerprint must match the one below.", "list", _G, [], _EA,
          pattern=_PATH, max_length=1024, max_items=512, item_label="Location",
          item_hint="/usr/lib/libtesseract.so.5",
          item_error="a full location on this server starting with /", empty_unset=True,
          weaker="change", warning="Different program libraries will be trusted to open "
                                   "files from outside.", **pic),
        _pin(S, ocr, "runtime_libraries_sha256", "Program libraries fingerprint",
             "The combined fingerprint of the library files above. " + installed,
             "set of program libraries", pic, fingerprint_of="ocr_libraries"),
        _pin(S, ocr, "pillow_version", "Picture library version",
             "The exact version of the picture library installed with Lightwork, such as "
             "11.0.0.", "picture library", pic, pattern=_VERSION, max_length=64),
        _pin(S, ocr, "pillow_manifest_sha256", "Picture library fingerprint", installed,
             "picture library", pic, fingerprint_of="pillow"),
        _limit(S, ocr, "timeout_seconds", "Time limit for reading one picture",
               "Reading a picture stops after this long.", 30, pic, minimum=1, maximum=120,
               unit="seconds", warning=_LONGER_RUNS),
        _limit(S, ocr, "max_pixels", "Largest picture",
               "Pictures with more pixels than this are refused.", 40000000, pic,
               minimum=0.1, maximum=100, step=0.1, scale=1000000, unit="megapixels"),
        _limit(S, ocr, "max_output_bytes", "Text kept from one picture",
               "Reading stops once this much text has been read.", 1048576, pic, minimum=1,
               maximum=10240, scale=1024, unit="KB", warning=_MORE_TEXT),
        _limit(S, ocr, "max_memory_bytes", "Memory for reading one picture",
               "The most memory the text-recognition program may use.", 536870912, pic,
               minimum=64, maximum=2048, scale=1048576, unit="MB", warning=_MORE_MEMORY),

        S(old, "enable", "Read older Excel files",
          "Open older Excel workbooks sent as evidence with a separate, isolated reader. "
          "Needs isolated file reading on and older Excel workbooks allowed above.", "toggle",
          _G, False, _EA, weaker=True,
          warning="Older Excel files from outside, a format often used to hide harmful "
                  "content, will be opened on this server.", **xls),
        _pin(S, old, "xlrd_version", "Spreadsheet reader version",
             "The exact version of the spreadsheet reader installed with Lightwork, such as "
             "2.0.2.", "spreadsheet reader", xls, pattern=_VERSION, max_length=64),
        _pin(S, old, "xlrd_manifest_sha256", "Spreadsheet reader fingerprint", installed,
             "spreadsheet reader", xls, fingerprint_of="xlrd"),
        _pin(S, old, "olefile_version", "Office file reader version",
             "The exact version of the office file reader installed with Lightwork, such as "
             "0.47.", "office file reader", xls, pattern=_VERSION, max_length=64),
        _pin(S, old, "olefile_manifest_sha256", "Office file reader fingerprint", installed,
             "office file reader", xls, fingerprint_of="olefile"),
        _limit(S, old, "timeout_seconds", "Time limit for reading one workbook",
               "Reading a workbook stops after this long.", 15, xls, minimum=1, maximum=120,
               unit="seconds", warning=_LONGER_RUNS),
        _limit(S, old, "max_workbook_stream_bytes", "Largest workbook contents",
               "Workbooks whose contents are bigger than this are refused.", 33554432, xls,
               minimum=1, maximum=64, scale=1048576, unit="MB"),
        _limit(S, old, "max_record_bytes", "Largest single entry in a workbook",
               "Workbooks holding a bigger entry are refused.", 8388608, xls, minimum=1,
               maximum=16383, scale=1024, unit="KB"),
        _limit(S, old, "max_records", "Entries read per workbook",
               "Reading stops after this many entries.", 500000, xls, minimum=1,
               maximum=1000000, unit="entries"),
        _limit(S, old, "max_sheets", "Sheets read per workbook",
               "Workbooks with more sheets are refused.", 200, xls, minimum=1, maximum=256,
               unit="sheets"),
        _limit(S, old, "max_rows_per_sheet", "Rows read per sheet",
               "Sheets with more rows are refused.", 200000, xls, minimum=1,
               maximum=1048576, unit="rows"),
        _limit(S, old, "max_columns_per_sheet", "Columns read per sheet",
               "Sheets with more columns are refused.", 256, xls, minimum=1, maximum=256,
               unit="columns"),
        _limit(S, old, "max_cells", "Cells read per workbook",
               "Workbooks with more filled cells are refused.", 200000, xls, minimum=1,
               maximum=1000000, unit="cells"),
        _limit(S, old, "max_output_bytes", "Text kept from one workbook",
               "Reading stops once this much text has been read.", 1048576, xls, minimum=1,
               maximum=10240, scale=1024, unit="KB", warning=_MORE_TEXT),
        _limit(S, old, "max_memory_bytes", "Memory for reading one workbook",
               "The most memory the workbook reader may use.", 536870912, xls, minimum=64,
               maximum=2048, scale=1048576, unit="MB", warning=_MORE_MEMORY),
    )


def _evidence_records(S) -> tuple:
    common = {"subgroup": "AI evidence records"}
    reader = "maverick.ai_evidence_gateway"
    out = []
    for kind, noun, label, default in (("receipt", "receipts", "Evidence receipts", 1000000),
                                       ("packet", "packs", "Assurance packs", 100000)):
        out += [
            S("evidence_gateway", f"{kind}_max_total", f"{label} kept",
              f"The most evidence {noun} kept. New ones are refused once this is reached.",
              "number", _G, default, reader, minimum=1, maximum=100000000, integer=True,
              unit=noun, env=(f"MAVERICK_EVIDENCE_{kind.upper()}_MAX_TOTAL",), **common),
            S("evidence_gateway", f"{kind}_segment_rows", f"{label} per storage file",
              f"How many {noun} go in one storage file before a new file is started.",
              "number", _G, 4096, reader, minimum=1, maximum=1000000, integer=True,
              unit=noun, env=(f"MAVERICK_EVIDENCE_{kind.upper()}_SEGMENT_ROWS",), **common),
            S("evidence_gateway", f"{kind}_segment_bytes", f"Size of each {noun[:-1]} storage file",
              "A new storage file is started once one reaches this size.", "number", _G,
              67108864, reader, minimum=1, maximum=1024, integer=True, scale=1048576,
              unit="MB", env=(f"MAVERICK_EVIDENCE_{kind.upper()}_SEGMENT_BYTES",), **common),
        ]
    return tuple(out)


# ----------------------------------------------------------- identity connectors
def _identity_connectors(S) -> tuple:
    kernel = "maverick.ai_identity_governance_connectors"
    schedule = "maverick_dashboard.identity_governance_scheduler"
    top = "ai_identity_governance_connectors"
    out = [
        S(top, "enable", "Read access data from your identity services",
          "Lightwork reads which people and applications hold which access in the identity "
          "services turned on below. It only reads; it never changes them.", "toggle", _G,
          False, kernel, subgroup="Identity governance connectors",
          aliases="entra okta purview identity governance"),
        S(f"{top}.scheduler", "enable", "Collect identity data on a schedule",
          "Read the identity services below automatically in the background.", "toggle", _G,
          False, schedule, subgroup="Identity governance connectors", restart=True),
        S(f"{top}.scheduler", "poll_seconds", "Check for due collections every",
          "How often the schedule looks for collections that are due.", "number", _G, 60.0,
          schedule, subgroup="Identity governance connectors", minimum=5, maximum=3600,
          unit="seconds", restart=True),
    ]
    for name, label in _IDENTITY_PROVIDERS:
        out += _identity_provider(S, top, name, label, kernel, schedule)
    return tuple(out)


def _identity_address(S, section, name, label, kernel, sub):
    if name == "entra":
        return S(section, "base_url", f"{label} cloud",
                 "The Microsoft cloud your organisation's directory lives in.", "select", _G,
                 "https://graph.microsoft.com", kernel, choices=_ENTRA_CLOUDS, **sub)
    pattern, hint = ((_OKTA_URL, "https://yourcompany.okta.com") if name == "okta"
                     else (_PURVIEW_URL, "https://youraccount.purview.azure.com"))
    return S(section, "base_url", f"{label} address",
             f"The secure web address of your {label} account, such as {hint}.", "text", _G,
             "", kernel, pattern=pattern, max_length=300, weaker="change",
             warning=f"Lightwork will send its {label} sign-in key to a different address.",
             **sub)


def _identity_provider(S, top, name, label, kernel, schedule) -> list:
    sub = {"subgroup": f"Identity connector: {label}"}
    section = f"{top}.{name}"
    timing = f"{top}.scheduler.providers.{name}"
    return [
        S(section, "enable", f"Read from {label}",
          f"Read access data from {label} with the sign-in key below.", "toggle", _G, False,
          kernel, **sub),
        S(section, "tenant_id", f"{label} organisation code",
          f"The code that identifies your organisation in {label}.", "text", _G, "", kernel,
          pattern=_ORG_ID, max_length=256, **sub),
        _identity_address(S, section, name, label, kernel, sub),
        S(section, "credential", f"{label} sign-in key",
          f"The access key Lightwork uses to read {label}. It is stored sealed and never "
          "shown again. A key set on your server is used first.", "secret", _G, "", kernel,
          max_length=16384, **sub),
        S(section, "timeout_seconds", "Time limit per request",
          f"How long one request to {label} may take.", "number", _G, 15.0, kernel,
          minimum=1, maximum=60, unit="seconds", **sub),
        S(section, "max_pages", "Pages read per collection",
          "The most result pages read in one collection.", "number", _G, 50, kernel,
          minimum=1, maximum=500, integer=True, unit="pages", **sub),
        S(section, "max_records", "Items read per collection",
          "The most people or applications read in one collection.", "number", _G, 2000,
          kernel, minimum=1, maximum=50000, integer=True, unit="items", **sub),
        S(section, "max_response_bytes", "Largest reply accepted",
          f"Replies from {label} bigger than this are refused.", "number", _G, 262144,
          kernel, minimum=1, maximum=1024, integer=True, scale=1024, unit="KB", **sub),
        S(section, "page_size", "Items per page",
          "How many items are asked for in each result page.", "number", _G, 100, kernel,
          minimum=1, maximum=200, integer=True, unit="items", **sub),
        S(section, "retry_attempts", "Tries per request",
          "How many times a failed request is tried.", "number", _G, 3, kernel, minimum=1,
          maximum=5, integer=True, unit="tries", **sub),
        S(timing, "enable", f"Collect from {label} on a schedule",
          f"Include {label} in the scheduled collection. Needs reading from {label} on.",
          "toggle", _G, False, schedule, **sub),
        S(timing, "interval_seconds", "Collect every",
          "How often a new collection is started.", "number", _G, 3600, schedule,
          minimum=1, maximum=1440, integer=True, scale=60, unit="minutes", **sub),
        S(timing, "retry_base_seconds", "Wait before the first retry",
          "How long to wait after a failed collection; later retries wait longer.", "number",
          _G, 30, schedule, minimum=1, maximum=3600, integer=True, unit="seconds", **sub),
        S(timing, "retry_max_seconds", "Longest wait between retries",
          "Retries never wait longer than this. It can't be shorter than the first wait.",
          "number", _G, 900, schedule, minimum=1, maximum=86400, integer=True,
          unit="seconds", **sub),
        S(timing, "max_attempts_per_slot", "Tries per collection",
          "How many times one collection is tried before it waits for the next one.",
          "number", _G, 3, schedule, minimum=1, maximum=10, integer=True, unit="tries",
          **sub),
        S(timing, "lease_seconds", "Time a collection is held by one worker",
          "If a worker stops, another may take over the collection after this long.",
          "number", _G, 3600, schedule, minimum=1, maximum=1440, integer=True, scale=60,
          unit="minutes", **sub),
        S(timing, "history_limit", "Past collections kept",
          "How many earlier collections are kept for comparison.", "number", _G, 8, schedule,
          minimum=1, maximum=32, integer=True, unit="collections", **sub),
        S(timing, "max_snapshot_items", "Items kept per collection",
          "The most people or applications kept from one collection.", "number", _G, 5000,
          schedule, minimum=1, maximum=10000, integer=True, unit="items", **sub),
        S(timing, "max_delta_digests", "Changes remembered between collections",
          "The most individual changes kept when comparing two collections.", "number", _G,
          256, schedule, minimum=0, maximum=512, integer=True, unit="changes", **sub),
    ]


def _identity_controls(S) -> tuple:
    reader = "maverick_dashboard.identity_governance_runtime"
    top = "ai_identity_governance_connectors.controls"
    prod = f"{top}.production"
    sub = {"subgroup": "Identity controls"}
    return (
        S(top, "enable", "Identity controls",
          "Turn on the identity controls below. Needs reading access data from your identity "
          "services on.", "toggle", _G, False, reader, **sub),
        S(f"{top}.change_coupling", "enable", "Link access changes to AI risk",
          "When access changes in an identity service, act on the AI systems affected, as "
          "chosen in the next two settings. At least one of them must be on.", "toggle", _G,
          False, reader, **sub),
        S(f"{top}.change_coupling", "dynamic_risk", "Update AI risk on access changes",
          "Raise or lower the risk of affected AI systems when their access changes.",
          "toggle", _G, False, reader, **sub),
        S(f"{top}.change_coupling", "alerts", "Raise an alert on access changes",
          "Send an alert when the access of an AI system changes.", "toggle", _G, False,
          reader, **sub),
        S(f"{top}.federation", "enable", "Use identity groups for agent permissions",
          "What agents acting for a person may do also follows that person's groups in "
          "Microsoft Entra or Okta.", "toggle", _G, False, reader, weaker=True,
          warning="What agents may do will also depend on group membership in your identity "
                  "service.", **sub),
        S(f"{top}.conditional_access", "enable", "Follow conditional access decisions",
          "Check your identity service's conditional access decisions before agents act. "
          "Needs identity groups for agent permissions on.", "toggle", _G, False, reader,
          **sub),
        S(f"{top}.purview_writeback", "enable", "Write data labels back to Microsoft Purview",
          "Send the data labels Lightwork decides to Microsoft Purview. Needs identity groups "
          "for agent permissions on.", "toggle", _G, False, reader, weaker=True,
          warning="Lightwork will change data labels in Microsoft Purview.", **sub),
        S(prod, "enable", "Run the full identity control service",
          "Keep identity control decisions and their follow-up work in their own records for "
          "each workspace, with the limits below.", "toggle", _G, False, reader, **sub),
        S(prod, "mapping_revision", "Group mapping version",
          "Raise this by one after you change how groups map to agent permissions, so "
          "earlier decisions are not used again.", "number", _G, 1, reader, minimum=1,
          maximum=1000000, integer=True, unit="", weaker="lower",
          warning="Decisions made under an earlier group mapping could be used again.", **sub),
        S(prod, "mapping_retention_seconds", "Keep group mapping records for",
          "How long records of group mappings are kept.", "number", _G, 86400, reader,
          minimum=1, maximum=8784, integer=True, scale=3600, unit="hours", weaker="lower",
          warning="Group mapping records will be deleted sooner.", **sub),
        S(prod, "max_authority_records", "Identity records kept",
          "The most identity control records kept for a workspace.", "number", _G, 10000,
          reader, minimum=1, maximum=10000, integer=True, unit="records", **sub),
        S(prod, "max_observation_age_seconds", "Oldest identity reading used",
          "Identity readings older than this are not used for decisions.", "number", _G, 300,
          reader, minimum=1, maximum=3600, integer=True, unit="seconds", weaker="higher",
          warning="Decisions may rely on older identity information.", **sub),
        S(prod, "max_future_skew_seconds", "Allowed clock difference",
          "How far ahead of this server's clock an identity service's time may be.",
          "number", _G, 30, reader, minimum=0, maximum=300, integer=True, unit="seconds",
          weaker="higher", warning="Readings with a larger clock difference will be used.",
          **sub),
        S(prod, "outcome_max_attempts", "Tries per follow-up",
          "How many times a follow-up to an access change is tried.", "number", _G, 5,
          reader, minimum=1, maximum=20, integer=True, unit="tries", **sub),
        S(prod, "outcome_retry_base_seconds", "Wait before retrying a follow-up",
          "How long to wait after a failed follow-up; later retries wait longer.", "number",
          _G, 30, reader, minimum=1, maximum=86400, integer=True, unit="seconds", **sub),
        S(prod, "outcome_retry_max_seconds", "Longest wait between follow-up retries",
          "Retries never wait longer than this.", "number", _G, 3600, reader, minimum=1,
          maximum=604800, integer=True, unit="seconds", **sub),
        S(prod, "outcome_lease_seconds", "Time a follow-up is held by one worker",
          "If a worker stops, another may take over the follow-up after this long.",
          "number", _G, 60, reader, minimum=1, maximum=3600, integer=True, unit="seconds",
          **sub),
        S(prod, "outcome_signal_validity_seconds", "Access change signals stay valid for",
          "After this, a signal about an access change is no longer acted on.", "number", _G,
          86400, reader, minimum=1, maximum=527040, integer=True, scale=60, unit="minutes",
          weaker="higher", warning="Older access change signals will still be acted on.",
          **sub),
        S(prod, "purview_max_attempts", "Tries per Purview change",
          "How many times one change in Microsoft Purview is tried.", "number", _G, 3, reader,
          minimum=1, maximum=10, integer=True, unit="tries", **sub),
        S(prod, "purview_operation_lease_seconds", "Time a Purview change is held by one worker",
          "If a worker stops, another may take over the change after this long.", "number",
          _G, 60, reader, minimum=5, maximum=300, integer=True, unit="seconds", **sub),
    )


# --------------------------------------------------------- third-party management
def _third_party(S) -> tuple:
    top = "third_party_management"
    contracts = {"subgroup": "Third-party contracts"}
    reports = {"subgroup": "Executive vendor reports"}
    ratings = {"subgroup": "Vendor risk ratings"}
    portal = {"subgroup": "Supplier collaboration portal"}
    rc = "maverick_dashboard.third_party_contracts_composition"
    rr = "maverick.third_party_executive_reports"
    rp = "maverick_dashboard.third_party_intelligence_provider_composition"
    rs = "maverick_dashboard.third_party_intelligence_scheduler"
    rt = "maverick.third_party_collaboration"
    prov = f"{top}.intelligence.providers"

    def host(key, label, provider):
        return S(prov, key, f"{label} address",
                 f"The server name of your {label} account, without https://, such as "
                 f"api.example.com. Fill it in only when {provider} is ticked above.", "text",
                 _G, "", rp, pattern=_OPT_HOST, max_length=253, weaker="change",
                 warning="Details of your vendors will be sent to a different address.",
                 **ratings)

    return (
        S(f"{top}.contracts", "authority_max_age_seconds", "Vendor details stay current for",
          "Contract records use vendor details no older than this.", "number", _G, 604800,
          rc, minimum=1, maximum=525600, integer=True, scale=60, unit="minutes",
          weaker="higher", warning="Contract records may be based on older vendor details.",
          **contracts),
        S(f"{top}.contracts", "max_records", "Contract records kept",
          "The most contract and engagement records kept.", "number", _G, 100000, rc,
          minimum=1, maximum=1000000, integer=True, unit="records", **contracts),
        S(f"{top}.contracts", "retention_seconds", "Keep contract records for",
          "How long closed contract records are kept.", "number", _G, 31536000, rc,
          minimum=1, maximum=3650, integer=True, scale=86400, unit="days", weaker="lower",
          warning="Contract records will be deleted sooner.", **contracts),

        S(f"{top}.executive_reports", "download_token_seconds", "Report download links last",
          "How long a link to download an executive report works.", "number", _G, 300, rr,
          minimum=0.5, maximum=1440, step=0.5, integer=True, scale=60, unit="minutes",
          weaker="higher",
          warning="Report download links will work for longer if they are passed on.",
          **reports),
        S(f"{top}.executive_reports", "max_pdf_bytes", "Largest report",
          "Reports bigger than this are not produced.", "number", _G, 524288, rr, minimum=16,
          maximum=4096, integer=True, scale=1024, unit="KB", **reports),
        S(f"{top}.executive_reports", "max_reports", "Reports kept",
          "The most executive reports kept.", "number", _G, 10000, rr, minimum=1,
          maximum=1000000, integer=True, unit="reports", **reports),
        S(f"{top}.executive_reports", "max_sources", "Records per report",
          "The most vendor records one report may draw on.", "number", _G, 100, rr, minimum=1,
          maximum=500, integer=True, unit="records", **reports),
        S(f"{top}.executive_reports", "retention_seconds", "Keep reports for",
          "How long executive reports are kept.", "number", _G, 31536000, rr, minimum=1,
          maximum=3650, integer=True, scale=86400, unit="days", weaker="lower",
          warning="Executive reports will be deleted sooner.", **reports),

        S(prov, "enable", "Fetch vendor risk ratings from outside providers",
          "Read vendor risk ratings from the providers ticked below, with the sign-in "
          "details set up for each one.", "toggle", _G, False, rp, weaker=True,
          warning="Lightwork will contact outside rating providers about your vendors.",
          **ratings),
        S(prov, "enabled_providers", "Rating providers",
          "The providers vendor ratings are read from. Choose at least one while ratings are "
          "on.", "multiselect", _G, [], rp, choices=_RATING_PROVIDERS, weaker="grow",
          warning="Details of your vendors will be sent to more outside providers.",
          **ratings),
        host("supplywisdom_host", "SupplyWisdom", "SupplyWisdom"),
        host("iss_corporate_solutions_host", "ISS Corporate Solutions",
             "ISS Corporate Solutions"),
        host("generic_approved_host", "Other approved provider", "Another approved provider"),
        S(prov, "timeout_seconds", "Time limit per provider request",
          "How long one request to a rating provider may take.", "number", _G, 20.0, rp,
          minimum=1, maximum=120, unit="seconds", **ratings),
        S(f"{prov}.scheduler", "enable", "Refresh vendor ratings on a schedule",
          "Read new ratings from the providers automatically in the background.", "toggle",
          _G, False, rs, restart=True, **ratings),
        S(f"{prov}.scheduler", "poll_seconds", "Refresh vendor ratings every",
          "How often ratings are read again.", "number", _G, 900.0, rs, minimum=1,
          maximum=1440, scale=60, unit="minutes", restart=True, **ratings),

        S(f"{top}.lifecycle.portal", "invitation_ttl_seconds", "Portal invitations last",
          "How long an invitation link sent to a supplier works.", "number", _G, 86400, rt,
          minimum=1, maximum=2160, integer=True, scale=3600, unit="hours", weaker="higher",
          warning="Portal invitations will work for longer if they are passed on.", **portal),
        S(f"{top}.lifecycle.portal", "max_artifact_bytes", "Largest supplier upload",
          "Files suppliers upload that are bigger than this are refused.", "number", _G,
          10485760, rt, minimum=1, maximum=100, integer=True, scale=1048576, unit="MB",
          weaker="higher", warning="Suppliers will be able to upload larger files.", **portal),
        S(f"{top}.lifecycle.portal", "max_artifacts", "Uploads per supplier request",
          "The most files a supplier may upload for one request. Zero means none.", "number",
          _G, 20, rt, minimum=0, maximum=100, integer=True, unit="files", weaker="higher",
          warning="Suppliers will be able to upload more files.", **portal),
        S(f"{top}.lifecycle.portal", "max_messages", "Messages per supplier request",
          "The most messages kept for one request.", "number", _G, 100, rt, minimum=1,
          maximum=1000, integer=True, unit="messages", **portal),
        S(f"{top}.lifecycle.portal", "retention_seconds", "Keep portal records for",
          "How long portal messages and uploads are kept.", "number", _G, 31536000, rt,
          minimum=1, maximum=3660, integer=True, scale=86400, unit="days", weaker="lower",
          warning="Portal messages and uploads will be deleted sooner.", **portal),
    )


# ---------------------------------------------------------- tech-risk compliance
def _tech_risk(S) -> tuple:
    feature = "tech_risk_compliance.continuous_evidence"
    timing = f"{feature}.scheduler"
    studio = "tech_risk_compliance.grc_studio"
    sched = "maverick_dashboard.trc_continuous_evidence_scheduler"
    stock = "maverick_dashboard.trc_stock_evidence_composition"
    rg = "maverick_dashboard.no_code_grc_studio_composition"
    ev = {"subgroup": "Continuous evidence"}
    gs = {"subgroup": "Compliance studio"}
    return (
        S(feature, "enabled_collectors", "Where evidence is collected from",
          "The checks and systems continuous evidence may collect from. Choose at least one "
          "while continuous evidence is on.", "multiselect", _G, [], sched,
          choices=_COLLECTORS, weaker="grow",
          warning="Evidence will be collected from more systems.", **ev),
        S(f"{feature}.stock_collectors", "enable", "Use the built-in collectors for outside systems",
          "Collect evidence from the outside systems ticked above, through the sources your "
          "team sets up on the Continuous evidence page. Remove those sources before turning "
          "this off.", "toggle", _G, False, stock, **ev),
        S(timing, "enable", "Collect evidence on a schedule",
          "Collect due evidence automatically in the background.", "toggle", _G, False, sched,
          restart=True, **ev),
        S(timing, "poll_seconds", "Check for due evidence every",
          "How often the schedule looks for collections that are due.", "number", _G, 60.0,
          sched, minimum=5, maximum=3600, unit="seconds", **ev),
        S(timing, "enqueue_limit", "Collections queued per check",
          "The most due collections queued in one check.", "number", _G, 50, sched,
          minimum=1, maximum=500, integer=True, unit="collections", **ev),
        S(timing, "claim_limit", "Collections run per check",
          "The most queued collections started in one check.", "number", _G, 10, sched,
          minimum=1, maximum=100, integer=True, unit="collections", **ev),
        S(timing, "tenant_limit", "Workspaces handled per check",
          "The most workspaces checked in one pass.", "number", _G, 1000, sched, minimum=1,
          maximum=10000, integer=True, unit="workspaces", **ev),
        S(timing, "lease_seconds", "Time a collection is held by one worker",
          "If a worker stops, another may take over the collection after this long.",
          "number", _G, 120, sched, minimum=30, maximum=3600, integer=True, unit="seconds",
          **ev),
        S(timing, "retry_backoff_seconds", "Wait before retrying a failed collection",
          "How long a failed collection waits before it is tried again.", "number", _G, 30,
          sched, minimum=1, maximum=86400, integer=True, unit="seconds", **ev),

        S(studio, "max_import_bytes", "Largest studio import",
          "Imported studio definitions bigger than this are refused.", "number", _G, 2097152,
          rg, minimum=1, maximum=2048, integer=True, scale=1024, unit="KB", **gs),
        S(studio, "max_studios", "Studios kept",
          "The most GRC studios kept.", "number", _G, 10000, rg, minimum=1, maximum=10000,
          integer=True, unit="studios", **gs),
        S(studio, "retention_seconds", "Keep unused studio drafts for",
          "How long studio drafts that were never accepted are kept.", "number", _G,
          31536000, rg, minimum=1, maximum=3650, integer=True, scale=86400, unit="days",
          weaker="lower", warning="Studio drafts will be deleted sooner.", **gs),
    )


# ------------------------------------------- other governance module settings
def _governance_modules(S) -> tuple:
    ga = {"subgroup": "Governance agents"}
    ctx = "maverick.governance_agent_context"
    agents = "maverick.governance_agents"
    vault = {"subgroup": "Document vault"}
    att = {"subgroup": "Incident attachments"}
    ra = "maverick_dashboard.incident_attachment_metadata_composition"
    red = {"subgroup": "Red-team testing"}
    cost = {"subgroup": "AI cost collection"}
    loop = {"subgroup": "AI governance loop"}
    rl = "maverick_dashboard.ai_governance_loop_composition"
    media = {"subgroup": "Media provenance"}
    sandbox = {"subgroup": "Customer practice copies"}
    return (
        S("governance_agents", "context_projection_enable",
          "Give governance agents records from other modules",
          "Governance agents may read a short summary of records from the other governance "
          "modules as background for their work.", "toggle", _G, False, ctx, weaker=True,
          warning="Governance agents will see summaries of records from other modules.", **ga),
        S("governance_agents", "context_projection_max_records_per_source",
          "Records read from each module", "The most records read from one module for one "
          "request.", "number", _G, 100, ctx, minimum=1, maximum=500, integer=True,
          unit="records", **ga),
        S("governance_agents", "context_projection_max_context_items",
          "Background records per request", "The most background records given with one "
          "request.", "number", _G, 32, ctx, minimum=1, maximum=100, integer=True,
          unit="records", **ga),
        S("governance_agents", "context_projection_max_total_bytes",
          "Background text per request", "The most background text given with one request.",
          "number", _G, 2097152, ctx, minimum=1, maximum=10240, integer=True, scale=1024,
          unit="KB", **ga),
        S("governance_agents", "context_projection_max_record_bytes",
          "Text kept from each background record", "Longer records are shortened.", "number",
          _G, 16384, ctx, minimum=0.25, maximum=64, step=0.25, integer=True, scale=1024,
          unit="KB", **ga),
        S("governance_agents", "max_context_items", "Records an agent may be given",
          "The most records one governance agent task may be given.", "number", _G, 100,
          agents, minimum=1, maximum=100, integer=True, unit="records", **ga),
        S("governance_agents", "max_context_bytes", "Text an agent may be given",
          "The most text one governance agent task may be given.", "number", _G, 1048576,
          agents, minimum=1, maximum=1024, integer=True, scale=1024, unit="KB", **ga),
        S("governance_agents", "max_output_bytes", "Longest agent result",
          "Results longer than this are refused.", "number", _G, 262144, agents, minimum=1,
          maximum=256, integer=True, scale=1024, unit="KB", **ga),
        S("governance_agents", "retention_seconds", "Keep governance agent results for",
          "How long results of governance agent tasks are kept.", "number", _G, 31536000,
          agents, minimum=1, maximum=365, integer=True, scale=86400, unit="days",
          weaker="lower", warning="Governance agent results will be deleted sooner.", **ga),

        S("governance_inventory", "max_export_bytes", "Largest inventory export",
          "Inventory exports bigger than this are refused.", "number", _G, 10485760,
          "maverick_dashboard.shared_governance_inventory_composition",
          subgroup="Shared governance inventory", minimum=1, maximum=100, integer=True,
          scale=1048576, unit="MB"),

        S("governed_document_vault", "allowed_media_types", "Kinds of documents the vault accepts",
          "Only these kinds of documents can be stored.", "multiselect", _G,
          list(_ALL_DOCUMENT_MEDIA), "maverick.governed_document_vault",
          choices=_DOCUMENT_MEDIA, weaker="grow",
          warning="More kinds of documents from outside will be accepted into the vault.",
          **vault),
        S("governed_document_vault", "claim_lease_seconds", "Time a download is held by one worker",
          "If a worker stops, another may take over the download after this long.", "number",
          _G, 30, "maverick.governed_document_vault", minimum=5, maximum=300, integer=True,
          unit="seconds", **vault),
        S("governed_document_vault", "stream_chunk_bytes", "Download piece size",
          "Documents are sent in pieces of this size.", "number", _G, 65536,
          "maverick.governed_document_vault", minimum=4, maximum=1024, integer=True,
          scale=1024, unit="KB", **vault),

        S("incident_attachment_metadata", "allowed_media_types", "Kinds of incident attachments",
          "Only documents of these kinds can be attached to incidents.", "multiselect", _G,
          list(_ALL_DOCUMENT_MEDIA), ra, choices=_DOCUMENT_MEDIA, weaker="grow",
          warning="More kinds of documents will be accepted as incident attachments.", **att),
        S("incident_attachment_metadata", "attachment_ttl_seconds", "Attachments stay linked for",
          "After this, an attachment's link to its incident expires.", "number", _G, 604800,
          ra, minimum=1, maximum=8760, integer=True, scale=3600, unit="hours", **att),
        S("incident_attachment_metadata", "max_attachments", "Attachments kept",
          "The most incident attachments kept.", "number", _G, 100000, ra, minimum=1,
          maximum=1000000, integer=True, unit="attachments", **att),
        S("incident_attachment_metadata", "retention_seconds", "Keep attachment records for",
          "How long records of incident attachments are kept.", "number", _G, 31536000, ra,
          minimum=1, maximum=3650, integer=True, scale=86400, unit="days", weaker="lower",
          warning="Incident attachment records will be deleted sooner.", **att),

        S("red_team_assurance", "commitment_key", "Test answer sealing key",
          "A private key of at least 32 characters that seals agents' answers during tests. "
          "It is stored sealed and never shown again. A key set on your server is used first. "
          "Changing it ends test campaigns that are running.", "secret", _G, "",
          "maverick.red_team_assurance", pattern=r"\S{32,512}", max_length=512,
          env=("MAVERICK_RED_TEAM_COMMITMENT_KEY",), **red),
        S("red_team_assurance", "max_response_bytes", "Longest agent answer in a test",
          "Answers longer than this fail the test case.", "number", _G, 65536,
          "maverick.red_team_assurance", minimum=1, maximum=256, integer=True, scale=1024,
          unit="KB", **red),
        S("red_team_assurance", "scheduler_poll_seconds", "Check for scheduled campaigns every",
          "How often scheduled test campaigns are started.", "number", _G, 30.0,
          "maverick_dashboard.red_team_scheduler", minimum=5, maximum=3600, unit="seconds",
          restart=True, **red),

        S("ai_cost_roi", "collector_lookback_days", "Days collected each time",
          "How many whole days of spending each collection reads. It can't be more than the "
          "longest period below.", "number", _G, 1, "maverick.ai_cost_collectors", minimum=1,
          maximum=366, integer=True, unit="days", **cost),
        S("ai_cost_roi.collector_limits", "max_period_days", "Longest period one collection covers",
          "The most days one cost collection may read.", "number", _G, 93,
          "maverick.ai_cost_collectors", minimum=1, maximum=366, integer=True, unit="days",
          **cost),
        S("ai_cost_roi.collector_limits", "max_bytes_billed", "Most data a Google Cloud cost query reads",
          "Google Cloud charges for the data its cost queries read; bigger queries are "
          "refused.", "number", _G, 1000000000, "maverick.ai_cost_collectors", minimum=0.001,
          maximum=100, step=0.001, integer=True, scale=1000000000, unit="GB",
          weaker="higher",
          warning="Cost queries on Google Cloud may read more data, which Google charges for.",
          **cost),
        S("ai_cost_roi.collector_limits", "page_cap", "Pages read from a cloud per collection",
          "The most pages of cost records one collection reads from a cloud provider.",
          "number", _G, 20, "maverick.ai_cost_collectors", minimum=1, maximum=50,
          integer=True, unit="pages", weaker="higher",
          warning="Each cost collection may read more pages from your cloud provider.", **cost),
        S("ai_cost_roi.collector_limits", "record_cap", "Cost records read per collection",
          "The most cost records one collection keeps from a cloud provider.", "number", _G,
          1000, "maverick.ai_cost_collectors", minimum=1, maximum=1000, integer=True,
          unit="records", weaker="higher",
          warning="Each cost collection may read more records from your cloud provider.",
          **cost),
        S("ai_cost_roi.collector_limits", "page_size", "Cost records asked for per page",
          "How many cost records are asked for in each page from a cloud provider.", "number",
          _G, 200, "maverick.ai_cost_collectors", minimum=1, maximum=1000, integer=True,
          unit="records", weaker="higher",
          warning="Each request to your cloud provider may return more records at once.",
          **cost),
        S("ai_cost_roi.collector_limits", "timeout_seconds", "Time limit per cloud request",
          "How long one request to a cloud provider's cost service may take.", "number", _G,
          20.0, "maverick.ai_cost_collectors", minimum=1, maximum=60, unit="seconds",
          weaker="higher", warning="A slow cloud provider request will be waited on for longer.",
          **cost),

        S("ai_governance_loop", "enable", "Run the AI governance loop",
          "Work through AI governance follow-ups in the background. Needs AI inventory, "
          "dynamic AI risk, AI policy management and runtime guardrails turned on.", "toggle",
          _G, False, rl, **loop),
        S("ai_governance_loop", "lease_seconds", "Time an item is held by one worker",
          "If a worker stops, another may take over the item after this long.", "number", _G,
          120, rl, minimum=30, maximum=3600, integer=True, unit="seconds", **loop),

        S("ai_inventory", "record_cap", "AI systems read per platform",
          "The most AI systems read from one platform in one refresh.", "number", _G, 5000,
          "maverick.ai_inventory", subgroup="AI inventory", minimum=1, maximum=5000,
          integer=True, unit="systems"),
        S("ai_inventory", "missing_grace_runs", "Missed refreshes before a system is marked missing",
          "An AI system that stops appearing is marked missing after this many refreshes.",
          "number", _G, 2, "maverick.ai_inventory", subgroup="AI inventory", minimum=1,
          maximum=100, integer=True, unit="refreshes"),

        S("ai_entity_tasks", "authority_max_age_seconds", "AI inventory details stay current for",
          "Tasks about AI systems use inventory details no older than this.", "number", _G,
          604800, "maverick_dashboard.ai_entity_tasks_composition",
          subgroup="AI system tasks", minimum=1, maximum=525600, integer=True, scale=60,
          unit="minutes", weaker="higher",
          warning="Tasks may be based on older AI inventory details."),

        S("assessment_evidence_autopopulation", "max_records", "Proposals kept",
          "The most proposed answers kept.", "number", _G, 5000,
          "maverick_dashboard.assessment_evidence_autopopulation_composition",
          subgroup="Assessment evidence proposals", minimum=1, maximum=10000, integer=True,
          unit="proposals"),
        S("assessment_evidence_autopopulation", "max_evidence_records_per_proposal",
          "Evidence records per proposal", "The most evidence records one proposed answer "
          "may draw on.", "number", _G, 16,
          "maverick_dashboard.assessment_evidence_autopopulation_composition",
          subgroup="Assessment evidence proposals", minimum=1, maximum=32, integer=True,
          unit="records"),

        S("administration_document_access", "delivery_grant_ttl_seconds",
          "Download link after approval lasts",
          "How long the one-time download link lasts once access is approved. It can't be "
          "longer than the longest access allowed.", "number", _G, 60,
          "maverick.administration_document_access",
          subgroup="Administrator document access", minimum=5, maximum=300, integer=True,
          unit="seconds", weaker="higher",
          warning="Document download links will work for longer if they are passed on."),

        S("model_risk_assurance", "gate_promotions", "Check improvements before they are used",
          "Improvements agents make to themselves are put into use only after model "
          "assurance has checked them. Needs model assurance and the evidence graph turned "
          "on.", "toggle", _G, False, "maverick.model_risk_assurance", weaker=False,
          subgroup="Model assurance",
          warning="Improvements to agents will be put into use without the model assurance "
                  "check."),

        S("ai_media_provenance", "enable", "Track where media came from",
          "Record and check content credentials for pictures and media that agents make or "
          "receive.", "toggle", _G, False, "maverick.ai_media_provenance", **media),
        S("ai_media_provenance", "verification_adapter", "How content credentials are checked",
          "Use only the built-in checks, or also the content credentials tool installed on "
          "this server (its fingerprint is needed below).", "select", _G, "",
          "maverick.ai_media_provenance",
          choices=(("", "Built-in checks only (default)"),
                   ("c2patool", "Also the content credentials tool on this server")), **media),
        S("ai_media_provenance", "c2patool_executable_sha256", "Content credentials tool fingerprint",
          "Upload the same program that is on the server and Lightwork works out its "
          "fingerprint. The tool is not run if the program on the server does not match.",
          "fingerprint", _G, "", "maverick.ai_media_provenance", weaker="change",
          warning="A different program will be trusted to check content credentials.",
          **media),

        S("customer_sandbox_lifecycle", "enable", "Allow practice copies of workspaces",
          "Administrators may create a separate practice workspace from a copy of a "
          "workspace's module settings. Records and sign-in details are never copied.",
          "toggle", _G, False, "maverick.customer_sandbox_lifecycle", **sandbox),
        S("customer_sandbox_lifecycle", "source_revision", "Settings version on copies",
          "The version number recorded with each copy. Raise it after changing the settings "
          "you copy, so copies can be told apart.", "number", _G, 1,
          "maverick_dashboard.customer_sandbox_composition", minimum=1, maximum=2147483647,
          integer=True, unit="", **sandbox),

        S("assessments", "sources", "Where assessments look for documents",
          "The connected document sources assessments search, in this order. Only sources "
          "with sign-in details are used.", "multiselect", "Memory & learning",
          ["msgraph", "slack", "gdrive"], "maverick.config",
          choices=(("msgraph", "Microsoft 365 (SharePoint and OneDrive)"), ("slack", "Slack"),
                   ("gdrive", "Google Drive")), weaker="grow",
          warning="Assessments will search more of your connected document sources."),
    )


# ------------------------------------------------- outbound GRC vendor systems
def _outbound_vendors(S) -> tuple:
    reader = "maverick.grc_vendor_transports"
    sub = {"subgroup": "Outbound assurance records"}
    out = []
    for name, label, pattern, hint in _GRC_TARGETS:
        section = f"grc_outbound_sync.{name}"
        out += [
            S(section, "base_url", f"{label} address",
              f"The secure web address of your {label} system, such as {hint}.", "text", _G,
              "", reader, pattern=pattern, max_length=300, weaker="change",
              warning=f"Assurance records and the {label} sign-in key will be sent to a "
                      "different address.", **sub),
            S(section, "credential", f"{label} sign-in key",
              f"The access key Lightwork uses for {label}. It is stored sealed and never "
              "shown again. A key set on your server is used first.", "secret", _G, "",
              reader, max_length=8192, **sub),
            S(section, "timeout_seconds", f"Time limit per {label} request",
              f"How long one request to {label} may take.", "number", _G, 15.0, reader,
              minimum=1, maximum=60, unit="seconds", **sub),
            S(section, "max_response_bytes", f"Largest {label} reply accepted",
              f"Replies from {label} bigger than this are refused.", "number", _G, 262144,
              reader, minimum=1, maximum=1024, integer=True, scale=1024, unit="KB", **sub),
        ]
    return tuple(out)


# ------------------------------------------------------------ cross checks
_BOX = "ai_evidence_analysis.parser_sandbox.enable"
_OCR = "ai_evidence_analysis.ocr.enable"
_OLD_XLS = "ai_evidence_analysis.legacy_xls.enable"
_MEDIA = "ai_evidence_analysis.enabled_media_types"
_PICTURES = frozenset({"jpeg", "png"})


def cross_checks(effective: dict, by_id: dict, error: type) -> None:
    """Refuse governance combinations the kernel reports as a broken setup.

    Each rule mirrors a config_lint or module check, so a value the page
    accepts is one the module starts with instead of switching itself off.
    """
    _check_file_readers(effective, by_id, error)
    for name, _label in _IDENTITY_PROVIDERS:
        base = f"ai_identity_governance_connectors.scheduler.providers.{name}"
        _check_ordered(effective, by_id, error, f"{base}.retry_base_seconds",
                       f"{base}.retry_max_seconds")
    outcome = "ai_identity_governance_connectors.controls.production.outcome_retry"
    _check_ordered(effective, by_id, error, f"{outcome}_base_seconds",
                   f"{outcome}_max_seconds")
    _check_ordered(effective, by_id, error, "ai_cost_roi.collector_lookback_days",
                   "ai_cost_roi.collector_limits.max_period_days")


def _check_file_readers(effective, by_id, error) -> None:
    box, ocr, old = (effective.get(_BOX) is True, effective.get(_OCR) is True,
                     effective.get(_OLD_XLS) is True)
    media = {str(item) for item in effective.get(_MEDIA) or ()}
    for reader in (_OCR, _OLD_XLS):
        if effective.get(reader) is True and not box:
            raise error(f"{by_id[reader].label}: turn on “{by_id[_BOX].label}” first.")
    if box and not (ocr or old):
        raise error(f"{by_id[_BOX].label}: turn on “{by_id[_OCR].label}” or "
                    f"“{by_id[_OLD_XLS].label}” as well, or leave it off.")
    if ocr and not media & _PICTURES:
        raise error(f"{by_id[_OCR].label}: allow JPEG or PNG pictures in "
                    f"“{by_id[_MEDIA].label}” first.")
    if old and "xls" not in media:
        raise error(f"{by_id[_OLD_XLS].label}: allow older Excel workbooks in "
                    f"“{by_id[_MEDIA].label}” first.")
    if "xls" in media and not old:
        raise error(f"{by_id[_MEDIA].label}: older Excel workbooks also need "
                    f"“{by_id[_OLD_XLS].label}” turned on.")


def _check_ordered(effective, by_id, error, low_id: str, high_id: str) -> None:
    low, high = effective.get(low_id), effective.get(high_id)
    if (isinstance(low, (int, float)) and not isinstance(low, bool)
            and isinstance(high, (int, float)) and not isinstance(high, bool) and low > high):
        high_label = by_id[high_id].label
        raise error(f"{by_id[low_id].label} can't be more than "
                    f"{high_label[:1].lower() + high_label[1:]}.")
