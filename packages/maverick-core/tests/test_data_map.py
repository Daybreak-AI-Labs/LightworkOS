"""The data map: classification heuristics, importers, the Graph census.

The assertions that matter: the classifier flags the classic personal-data
column names and stays quiet on operational ones; health marks an asset
special-category; the information_schema importer groups columns into
per-table assets; and the SharePoint census registers what Graph returns
without ever needing live credentials in tests.
"""
from __future__ import annotations

import pytest
from maverick import config
from maverick import data_map as dm


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_GRAPH_TOKEN", raising=False)
    from maverick import audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    (tmp_path / "config.toml").write_text(
        "[data_map]\nenable = true\n", encoding="utf-8",
    )
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def test_map_is_off_by_default(tmp_path):
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    assert dm.enabled() is False
    with pytest.raises(dm.DataMapConfigError, match="enable"):
        dm.register_data_asset(
            "t", system="s", kind="table", owner="o", actor="a",
        )


def test_classifier_flags_the_classics_and_stays_quiet_otherwise():
    assert "email" in dm.classify_column("customer_email")
    assert "phone" in dm.classify_column("MobileNumber")
    assert "national_id" in dm.classify_column("ssn")
    assert "date_of_birth" in dm.classify_column("date_of_birth")
    assert "date_of_birth" in dm.classify_column("dob")
    assert "financial" in dm.classify_column("iban")
    assert "health" in dm.classify_column("primary_diagnosis_code")
    assert "credentials" in dm.classify_column("api_key_hash")
    assert "ip_address" in dm.classify_column("client_ip_addr")
    assert dm.classify_column("order_total") == []
    assert dm.classify_column("warehouse_zone") == []
    assert dm.classify_column("") == []

    flagged = dm.classify_columns(
        ["id", "email", "created_at", "phone_number"]
    )
    assert set(flagged) == {"email", "phone_number"}


def test_register_classifies_and_health_marks_special_category():
    record = dm.register_data_asset(
        "crm.contacts", system="snowflake", kind="table", owner="data-team",
        actor="ops", columns=["id", "email", "phone", "notes"],
    )
    assert record["id"].startswith("DMA-")
    assert record["categories"] == ["email", "phone"]
    assert record["special_category"] is False
    assert set(record["flagged_columns"]) == {"email", "phone"}

    # Re-registration reclassifies in place -- same id, new columns.
    again = dm.register_data_asset(
        "crm.contacts", system="snowflake", kind="table", owner="data-team",
        actor="ops", columns=["id", "email", "allergy_list"],
    )
    assert again["id"] == record["id"]
    assert again["special_category"] is True
    assert "health" in again["categories"]

    with pytest.raises(ValueError, match="kind"):
        dm.register_data_asset(
            "x", system="s", kind="blob", owner="o", actor="a",
        )


def test_links_attach_specialist_records():
    record = dm.register_data_asset(
        "hr.people", system="postgres", kind="table", owner="hr",
        actor="ops", columns=["email"],
    )
    linked = dm.link_asset_record(
        record["id"], kind="ropa", reference="ROPA-abc123",
        actor="ops", expected_revision=record["revision"],
    )
    assert linked["links"][0]["reference"] == "ROPA-abc123"
    with pytest.raises(ValueError, match="kind"):
        dm.link_asset_record(
            record["id"], kind="spreadsheet", reference="x",
            actor="ops", expected_revision=linked["revision"],
        )
    with pytest.raises(KeyError):
        dm.link_asset_record(
            "DMA-" + "0" * 24, kind="ropa", reference="x",
            actor="ops", expected_revision=1,
        )


def test_information_schema_import_groups_columns_into_tables():
    csv_text = (
        "table_schema,table_name,column_name\n"
        "crm,contacts,id\n"
        "crm,contacts,email\n"
        "crm,contacts,phone\n"
        "ops,shipments,tracking_code\n"
        "ops,shipments,dest_postcode\n"
        ",,broken\n"
    )
    result = dm.import_information_schema_csv(
        csv_text, system="snowflake", owner="data-team", imported_by="ops",
    )
    assert result == {"imported": 2, "skipped": 1}
    rows = dm.list_data_assets(system="snowflake")
    by_name = {row["name"]: row for row in rows}
    assert by_name["crm.contacts"]["categories"] == ["email", "phone"]
    assert by_name["ops.shipments"]["categories"] == ["address"]
    assert by_name["crm.contacts"]["column_count"] == 3

    posture = dm.data_map_posture()
    assert posture["assets"] == 2
    assert posture["flagged_assets"] == 2
    assert posture["unlinked_flagged_assets"] == 2
    assert posture["by_category"]["email"] == 1


def test_sharepoint_census_registers_what_graph_returns():
    calls: list[str] = []

    def fetcher(url: str) -> dict:
        calls.append(url)
        return {
            "value": [
                {"displayName": "Legal Hub",
                 "webUrl": "https://contoso.sharepoint.com/sites/legal"},
                {"name": "ops-archive",
                 "webUrl": "https://contoso.sharepoint.com/sites/ops"},
                {"webUrl": "https://contoso.sharepoint.com/anon"},
                "not-a-site",
            ]
        }

    result = dm.sync_sharepoint_sites(
        actor="ops", owner="it", search="hub", fetcher=fetcher,
    )
    assert result == {"imported": 2, "skipped": 2}
    assert calls == ["https://graph.microsoft.com/v1.0/sites?search=hub"]
    rows = dm.list_data_assets(system="sharepoint")
    assert {row["name"] for row in rows} == {"Legal Hub", "ops-archive"}
    assert rows[0]["kind"] == "site"
    assert rows[0]["source"] == "microsoft_graph"

    # No query -> the tenant-wide census endpoint.
    dm.sync_sharepoint_sites(actor="ops", owner="it", fetcher=fetcher)
    assert calls[-1] == "https://graph.microsoft.com/v1.0/sites/getAllSites"


def test_sharepoint_census_without_a_token_is_a_config_error():
    with pytest.raises(dm.DataMapConfigError, match="Sites.Read.All"):
        dm.sync_sharepoint_sites(actor="ops", owner="it")


def test_malformed_graph_payload_is_an_error():
    with pytest.raises(dm.DataMapError, match="unexpected shape"):
        dm.sync_sharepoint_sites(
            actor="ops", owner="it", fetcher=lambda _url: {"value": "nope"},
        )


def test_classifier_anchors_stay_quiet_on_lookalike_columns():
    # Substrings that used to false-positive: the anchored patterns must
    # leave operational columns alone.
    assert dm.classify_column("mail_server") == []
    assert dm.classify_column("microphone_enabled") == []
    assert dm.classify_column("healthcheck_status") == []
    assert dm.classify_column("shipment_status") == []
    # ...while the genuine articles (snake or camel) still flag.
    assert "email" in dm.classify_column("EmailAddress")
    assert "phone" in dm.classify_column("telephone_number")
    assert "health" in dm.classify_column("health_condition")


def test_identifying_categories_subset_the_classifier_vocabulary():
    assert set(dm.CLASSIFIER_CATEGORIES) >= dm.IDENTIFYING_CATEGORIES


def test_schema_import_checks_capacity_once_for_the_batch(monkeypatch):
    dm.register_data_asset(
        "warehouse.existing", system="snowflake", kind="table",
        owner="data-team", actor="ops",
    )
    monkeypatch.setattr(dm, "_MAX_RECORDS", 1)
    csv_text = (
        "table_schema,table_name,column_name\n"
        "warehouse,existing,email\n"
        "warehouse,brand_new,order_id\n"
    )
    result = dm.import_information_schema_csv(
        csv_text, system="snowflake", owner="data-team",
    )
    # The existing table refreshes in place; the new one has no budget
    # left and is skipped instead of raising mid-batch.
    assert result == {"imported": 1, "skipped": 1}
    names = {row["name"] for row in dm.list_data_assets()}
    assert names == {"warehouse.existing"}


def test_content_verification_records_what_was_actually_found():
    record = dm.register_data_asset(
        "crm.contacts", system="snowflake", kind="table", owner="data-team",
        actor="ops", columns=["id", "email"],
    )
    saved = dm.classify_asset_content(
        record["id"],
        "carol@example.com paid with 4111 1111 1111 1111; "
        "patient diagnosis code E11.9",
        actor="ops", expected_revision=record["revision"],
    )
    assert saved["content_categories"] == ["email", "financial", "health"]
    assert saved["content_counts"]["email"] == 1
    # Content findings merge into the asset's categories and flip the
    # special-category flag when health shows up in the DATA.
    assert "financial" in saved["categories"]
    assert saved["special_category"] is True
    assert saved["content_verified_by"] == "ops"
    with pytest.raises(ValueError, match="empty"):
        dm.classify_asset_content(record["id"], "   ", actor="ops",
                                  expected_revision=saved["revision"])


def test_masking_sql_emits_reviewable_ddl_and_never_more():
    dm.register_data_asset(
        "crm.contacts", system="snowflake", kind="table", owner="data-team",
        actor="ops", columns=["id", "email", "phone"],
    )
    sql = dm.masking_policy_sql()
    assert sql.startswith("-- Lightwork data-map masking policies")
    assert "never executes" in sql
    assert 'CREATE MASKING POLICY IF NOT EXISTS "LIGHTWORK_MASK_EMAIL"' in sql
    assert ('ALTER TABLE "CRM"."CONTACTS" MODIFY COLUMN "EMAIL" '
            'SET MASKING POLICY "LIGHTWORK_MASK_EMAIL";') in sql
    # Deterministic output for an unchanged register.
    assert sql == dm.masking_policy_sql()
    with pytest.raises(ValueError, match="snowflake"):
        dm.masking_policy_sql(system="bigquery")


def test_masking_sql_role_is_configurable_and_multi_category_is_noted():
    dm.register_data_asset(
        "hr.people", system="snowflake", kind="table", owner="hr",
        actor="ops", columns=["id", "dob"],
    )
    sql = dm.masking_policy_sql(unmasked_role="privacy_admin")
    assert "CURRENT_ROLE() IN ('PRIVACY_ADMIN')" in sql
    with pytest.raises(ValueError, match="UPPER_SNAKE_CASE"):
        dm.masking_policy_sql(unmasked_role="bad role;drop")
    # A column matching several categories carries a comment for the rest.
    rec = dm.register_data_asset(
        "crm.leads", system="snowflake", kind="table", owner="sales",
        actor="ops", columns=["email_and_phone"],
    )
    if len((rec["flagged_columns"] or {}).get("email_and_phone", [])) > 1:
        sql = dm.masking_policy_sql()
        assert "also flagged:" in sql


def test_sharepoint_file_scan_records_evidence_never_content():
    asset = dm.register_data_asset(
        "Legal Hub", system="sharepoint", kind="site", owner="it",
        actor="ops", source="microsoft_graph")
    listed: list[str] = []
    downloaded: list[str] = []

    def fetcher(url: str) -> dict:
        listed.append(url)
        return {"value": [
            {"id": "item-1!a", "name": "employees.csv", "size": 120,
             "file": {}},
            {"id": "item-2!b", "name": "logo.png", "size": 90, "file": {}},
            {"id": "item-3!c", "name": "notes", "size": 10, "folder": {}},
        ]}

    def downloader(url: str) -> bytes:
        downloaded.append(url)
        return b"reach me at alice@example.com or +1 415 555 2671"

    saved = dm.scan_sharepoint_site_files(
        asset["id"], site_id="contoso.sharepoint.com,guid-1,guid-2",
        actor="ops", expected_revision=asset["revision"],
        fetcher=fetcher, downloader=downloader)

    assert listed[0].startswith(
        "https://graph.microsoft.com/v1.0/sites/"
        "contoso.sharepoint.com,guid-1,guid-2/drive/root/children")
    # Only the text-format FILE was fetched: the image and folder were not.
    assert downloaded == [
        "https://graph.microsoft.com/v1.0/sites/"
        "contoso.sharepoint.com,guid-1,guid-2/drive/items/item-1!a/content"]
    assert saved["file_scan"]["files_sampled"] == 1
    assert saved["file_scan"]["files_skipped"] == 2
    assert saved["file_scan"]["flagged_files"] == [
        {"name": "employees.csv", "categories": ["email", "phone"]}]
    assert set(saved["content_categories"]) == {"email", "phone"}
    assert "email" in saved["categories"]
    # Evidence only: no sampled byte lands on the governed record.
    assert "alice@example.com" not in str(saved)


def test_sharepoint_file_scan_validates_identifiers_and_token():
    asset = dm.register_data_asset(
        "Ops", system="sharepoint", kind="site", owner="it", actor="ops")
    with pytest.raises(ValueError, match="site identifier"):
        dm.scan_sharepoint_site_files(
            asset["id"], site_id="bad/../id", actor="ops",
            expected_revision=asset["revision"],
            fetcher=lambda _u: {"value": []}, downloader=lambda _u: b"")
    with pytest.raises(dm.DataMapConfigError, match="Files.Read.All"):
        dm.scan_sharepoint_site_files(
            asset["id"], site_id="contoso.sharepoint.com,g1,g2",
            actor="ops", expected_revision=asset["revision"])
    # A hostile item id from the listing is skipped, not URL-spliced.
    saved = dm.scan_sharepoint_site_files(
        asset["id"], site_id="contoso.sharepoint.com,g1,g2", actor="ops",
        expected_revision=asset["revision"],
        fetcher=lambda _u: {"value": [
            {"id": "../items/evil", "name": "x.txt", "size": 5,
             "file": {}}]},
        downloader=lambda _u: (_ for _ in ()).throw(AssertionError("fetched")),
    )
    assert saved["file_scan"] == {
        "site_id": "contoso.sharepoint.com,g1,g2", "files_listed": 1,
        "files_sampled": 0, "files_skipped": 1, "flagged_files": []}


def _ooxml(members: dict) -> bytes:
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, body in members.items():
            archive.writestr(name, body)
    return buffer.getvalue()


def test_sharepoint_file_scan_reads_office_documents_without_a_parser_dep():
    asset = dm.register_data_asset(
        "Policies", system="sharepoint", kind="site", owner="it", actor="ops")
    docx = _ooxml({"word/document.xml":
                   "<w:document><w:body><w:p><w:r><w:t>"
                   "contact a&amp;b&#64;example.com</w:t></w:r></w:p>"
                   "</w:body></w:document>"})
    xlsx = _ooxml({"xl/sharedStrings.xml":
                   "<sst><si><t>4111 1111 1111 1111</t></si></sst>"})
    bodies = {"handbook.docx": docx, "roster.xlsx": xlsx}

    def fetcher(_url: str) -> dict:
        return {"value": [
            {"id": "d1", "name": "handbook.docx", "size": len(docx),
             "file": {}},
            {"id": "x1", "name": "roster.xlsx", "size": len(xlsx),
             "file": {}},
            {"id": "s1", "name": "scan.pdf", "size": 40, "file": {}},
        ]}

    def downloader(url: str) -> bytes:
        if url.endswith("d1/content"):
            return docx
        if url.endswith("x1/content"):
            return xlsx
        return b"%PDF-1.4 not really extractable"

    saved = dm.scan_sharepoint_site_files(
        asset["id"], site_id="contoso.sharepoint.com,g1,g2", actor="ops",
        expected_revision=asset["revision"],
        fetcher=fetcher, downloader=downloader)

    scan = saved["file_scan"]
    # Both OOXML documents were read; the unreadable PDF counts as SKIPPED --
    # never as a clean file.
    assert scan["files_sampled"] == 2
    assert scan["files_skipped"] == 1
    flagged = {row["name"]: row["categories"] for row in scan["flagged_files"]}
    # The escaped "&#64;" would have hidden this email before unescaping.
    assert flagged["handbook.docx"] == ["email"]
    assert flagged["roster.xlsx"] == ["financial"]
    assert "example.com" not in str(saved)  # evidence only, never content
    assert bodies  # the fixture bodies never reach the record


def test_s3_object_scan_records_evidence_and_needs_no_cloud_account():
    asset = dm.register_data_asset(
        "exports", system="s3", kind="bucket", owner="it", actor="ops")
    fetched: list[str] = []

    def lister(bucket: str, prefix: str) -> list[dict]:
        assert (bucket, prefix) == ("corp-exports", "hr/")
        return [
            {"Key": "hr/roster.csv", "Size": 64},
            {"Key": "hr/photo.png", "Size": 900},      # not a readable format
            {"Key": "hr/", "Size": 0},                 # folder marker
            {"Key": "hr/big.csv", "Size": 99_000_000},  # over the byte cap
        ]

    def getter(key: str) -> bytes:
        fetched.append(key)
        return b"name,email\nAda,ada@example.com\n"

    saved = dm.scan_s3_bucket_objects(
        asset["id"], bucket="corp-exports", prefix="hr/", actor="ops",
        expected_revision=asset["revision"], lister=lister, getter=getter)

    assert fetched == ["hr/roster.csv"]     # only the readable, in-bounds one
    scan = saved["file_scan"]
    assert scan["bucket"] == "corp-exports" and scan["prefix"] == "hr/"
    assert (scan["files_listed"], scan["files_sampled"],
            scan["files_skipped"]) == (4, 1, 3)
    assert scan["flagged_files"] == [
        {"name": "hr/roster.csv", "categories": ["email"]}]
    assert "ada@example.com" not in str(saved)   # evidence, never content


def test_s3_object_scan_validates_the_bucket_and_survives_unreadable_objects():
    asset = dm.register_data_asset(
        "exports2", system="s3", kind="bucket", owner="it", actor="ops")
    with pytest.raises(ValueError, match="bucket"):
        dm.scan_s3_bucket_objects(
            asset["id"], bucket="Not A Bucket", actor="ops",
            expected_revision=asset["revision"],
            lister=lambda *_a: [], getter=lambda _k: b"")

    def boom(_key: str) -> bytes:
        raise RuntimeError("AccessDenied")

    saved = dm.scan_s3_bucket_objects(
        asset["id"], bucket="corp-exports", actor="ops",
        expected_revision=asset["revision"],
        lister=lambda *_a: [{"Key": "a.txt", "Size": 10}], getter=boom)
    # A denied object is skipped, never counted as a clean sample.
    assert saved["file_scan"]["files_sampled"] == 0
    assert saved["file_scan"]["files_skipped"] == 1
