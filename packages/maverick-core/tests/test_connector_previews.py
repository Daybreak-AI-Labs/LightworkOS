"""Structured consequence previews for governed connector writes.

The property under test throughout: **reversibility is earned, never
asserted.** A plan reports ``reversible=True`` only when it is holding the
thing that inverts the write -- prior field values read back from the record,
or a created record's id it will read out of the create response. Every gap (a
failed restore read, a field the read didn't return, a full-replace PUT, a
DELETE, an unknown connector, restore reads switched off) must fail closed to
``undo=None``, which makes ``run_saga`` refuse before any effect.

Network-free: connector I/O is scripted, so the adapter is exercised without
touching the network, and every read/write it *would* have made is asserted.
"""
from __future__ import annotations

import json

import pytest
from maverick import connector_previews as cp
from maverick import earned_autonomy as ea
from maverick.governed_rest import RestConnector

SF_PATH = "/services/data/v60.0/sobjects/Opportunity/006xx0000000001AAA"
SF_COLLECTION = "/services/data/v60.0/sobjects/Opportunity"
#: A fabricated 32-hex ServiceNow sys_id -- the shape the Table API uses.
SN_ID = "a1b2c3d4e5f60718293a4b5c6d7e8f90"  # pragma: allowlist secret
SN_PATH = f"/api/now/table/incident/{SN_ID}"


class FakeConnector:
    """A governed connector with scripted I/O and the REAL ``preview_write``.

    Delegating the preview keeps the no-network validation path identical to
    production while letting a test dictate exactly what the API returns.
    """

    def __init__(self, name="salesforce", *, read="", writes=()):
        self.name = name
        self._read = read
        self._writes = list(writes)
        self.reads: list[dict] = []
        self.writes: list[dict] = []
        self._inner = RestConnector(
            name=name, base_url_env="X_BASE", token_env="X_TOKEN")

    def preview_write(self, params: dict) -> str:
        return self._inner.preview_write(params)

    def read(self, params: dict) -> str:
        self.reads.append(dict(params))
        return self._read() if callable(self._read) else self._read

    def write(self, params: dict) -> str:
        self.writes.append(dict(params))
        if self._writes:
            nxt = self._writes.pop(0)
            return nxt() if callable(nxt) else nxt
        return json.dumps({"id": "006NEW000000001AAA", "success": True})


#: Salesforce's optimistic-concurrency token, as a capture read returns it.
SF_STAMP = "2026-07-01T12:00:00.000+0000"
#: The same stamp after our own write moved it -- what an undo compares against.
SF_AFTER = "2026-07-01T12:00:05.000+0000"
#: The query the Salesforce dialect sends to capture a one-field Amount patch.
SF_AMOUNT_QUERY = {"fields": "Amount,LastModifiedDate"}
#: The ServiceNow capture query for a one-field cost patch: raw values only.
SN_COST_QUERY = {
    "sysparm_display_value": "false",
    "sysparm_exclude_reference_link": "true",
    "sysparm_fields": "cost,sys_mod_count",
}


def _sf_record(stamp=SF_STAMP, **fields) -> str:
    return json.dumps({"Id": "006xx0000000001AAA", "Name": "Acme",
                       "LastModifiedDate": stamp, **fields})


def _sn_record(mod_count="3", **fields) -> str:
    return json.dumps({"result": {"sys_id": "a" * 32,
                                  "sys_mod_count": mod_count, **fields}})


def _patch(path=SF_PATH, **body):
    return {"op": "patch", "path": path, "body": body}


def _script(*responses):
    """Scripted reads, consumed in order, for a connector's ``read``."""
    it = iter(responses)
    return lambda: next(it)


def _sf_reads(before: dict, after: dict, *, stamp=SF_STAMP, moved=SF_AFTER):
    """The four reads one reversible Salesforce patch makes, in order.

    capture (plan time) -> re-check before writing (do, so an edit made while
    the card waited for approval aborts with no effect) -> post-write snapshot
    (do, because a 204 carries no before-image) -> re-check before restoring
    (undo). Tests that care about a specific read override it individually.
    """
    return _script(_sf_record(stamp=stamp, **before),
                   _sf_record(stamp=stamp, **before),
                   _sf_record(stamp=moved, **after),
                   _sf_record(stamp=moved, **after))


class TestDialects:
    def test_salesforce_parses_object_and_id_from_an_sobject_path(self):
        d = cp.dialect_for("salesforce")
        assert d.target(SF_PATH) == ("Opportunity", "006xx0000000001AAA")
        assert d.entity(SF_PATH) == "Opportunity/006xx0000000001AAA"

    def test_salesforce_collection_path_is_not_a_record(self):
        # POSTing to the collection creates a record; it addresses none yet.
        assert cp.dialect_for("salesforce").target(SF_COLLECTION) is None

    def test_servicenow_parses_table_and_sys_id(self):
        d = cp.dialect_for("servicenow")
        assert d.target(SN_PATH) == ("incident", SN_ID)

    def test_servicenow_unwraps_result_envelope(self):
        d = cp.dialect_for("servicenow")
        assert d.unwrap({"result": {"number": "INC1"}}) == {"number": "INC1"}
        assert d.unwrap({"result": [{"number": "INC1"}]}) == {"number": "INC1"}
        # Ambiguous: a query matching several rows is not "the" record.
        assert d.unwrap({"result": [{"a": 1}, {"b": 2}]}) is None
        assert d.unwrap({"result": []}) is None

    def test_created_id_read_from_each_vendors_create_response(self):
        assert cp.dialect_for("salesforce").created_id(
            {"id": "006NEW000000001AAA", "success": True}) == "006NEW000000001AAA"
        assert cp.dialect_for("servicenow").created_id(
            {"result": {"sys_id": "f" * 32}}) == "f" * 32
        assert cp.dialect_for("salesforce").created_id({"success": True}) is None

    def test_a_query_string_does_not_defeat_record_detection(self):
        # The id is the last PATH segment. Matching against the raw string would
        # read the id as "a1b2...?sysparm_fields=cost", find no record, and
        # silently downgrade a perfectly restorable write to irreversible.
        d = cp.dialect_for("servicenow")
        assert d.target(
            f"{SN_PATH}?sysparm_fields=cost&sysparm_limit=1") == (
                "incident", SN_ID)
        assert cp.dialect_for("salesforce").target(f"{SF_PATH}?fields=Amount") == (
            "Opportunity", "006xx0000000001AAA")

    def test_a_percent_encoded_path_matches_its_decoded_form(self):
        encoded = "/services/data/v60.0/sobjects%2FOpportunity%2F006xx0000000001AAA"
        assert cp.dialect_for("salesforce").target(encoded) == (
            "Opportunity", "006xx0000000001AAA")

    def test_path_matching_is_anchored_rather_than_a_suffix_match(self):
        # An unanchored pattern accepts ANY prefix, so a path that merely ends
        # the right way is claimed as this vendor's. That matters most for the
        # collection: matching it is what licenses a POST to earn a DELETE built
        # by concatenation, so a near-miss path would earn a compensation aimed
        # at a URL this dialect never modelled. Refusing costs a human review;
        # accepting costs an unrelated destructive write.
        sf, sn = cp.dialect_for("salesforce"), cp.dialect_for("servicenow")
        assert sf.collection(SF_COLLECTION) == "Opportunity"
        assert sn.collection("/api/now/table/incident") == "incident"
        for near_miss in ("/proxy/services/data/v60.0/sobjects/Opportunity",
                          "/sobjects/Opportunity",
                          "/services/data/v60.0/sobjects/Opportunity/extra"):
            assert sf.collection(near_miss) is None
            assert sf.target(f"{near_miss}/006xx0000000001AAA") is None
        for near_miss in ("/proxy/api/now/table/incident", "/table/incident"):
            assert sn.collection(near_miss) is None
            assert sn.target(f"{near_miss}/{SN_ID}") is None

    def test_servicenow_normalises_a_decorated_field_to_its_raw_value(self):
        # The capture GET pins sysparm_exclude_reference_link=true, but that is
        # a READ parameter with no write-echo equivalent: the same reference
        # field is bare from the capture and decorated in the echo.
        d = cp.dialect_for("servicenow")
        assert d.field_value(
            {"link": "https://x.service-now.com/api/now/table/sys_user/abc",
             "value": "abc"}) == "abc"
        assert d.field_value({"display_value": "Bob", "value": "abc"}) == "abc"
        assert d.field_value("plain") == "plain"
        # The generic dialect claims no such knowledge and changes nothing.
        assert cp.dialect_for("workday").field_value({"value": "abc"}) == {
            "value": "abc"}

    def test_unknown_connector_gets_the_incapable_generic_dialect(self):
        d = cp.dialect_for("workday")
        assert d.name == "generic"
        assert d.target(SF_PATH) is None  # knows no vendor's URL grammar
        assert d.is_money("Amount") is False
        assert d.restore_query(["Amount"]) == {}
        # No token field means it can never promise a non-clobbering restore.
        assert d.concurrency_field == ""
        # And no id grammar means it can never vouch for a create response's id
        # well enough to concatenate it into a delete address.
        assert d.id_re is None


class TestMoneyCoercion:
    @pytest.mark.parametrize(("raw", "expected"), [
        (120000, 120000.0),
        (120000.50, 120000.50),
        ("120000.50", 120000.50),
        ("$120,000.50", 120000.50),
        ("USD;1200.00", 1200.0),          # ServiceNow currency field
        ({"value": "1200.00"}, 1200.0),   # ServiceNow display/value object
    ])
    def test_parses_the_shapes_these_apis_actually_return(self, raw, expected):
        assert cp._as_money(raw) == expected

    @pytest.mark.parametrize("raw", ["", "N/A", None, True, ["1"], {"x": 1},
                                     "nan", "inf", float("nan")])
    def test_non_money_is_none_not_zero(self, raw):
        # Zero would silently understate exposure; None means "no figure".
        assert cp._as_money(raw) is None


class TestValueComparisonRefusesToLaunderDifferences:
    """The comparison that decides "is somebody else's edit sitting here?".

    It is used in both directions -- the do-step corroborating its post-write
    snapshot, and the undo checking what it is about to overwrite -- so a false
    "same" is the failure that matters: it hands the undo a licence to destroy
    an edit while reporting the field untouched. A false "different" only
    forfeits an undo and routes to a human.
    """

    @pytest.mark.parametrize(("readback", "written"), [
        (7, 7), ("7", 7), (7, "7"), (120000, 120000.0),
        ("120000.00", 120000), ("$120,000.00", 120000),
        ("Closed Won", "Closed Won"), (" Closed Won ", "Closed Won"),
        (None, None),
    ])
    def test_a_service_restating_our_own_value_is_not_an_edit(
            self, readback, written):
        assert cp._same_value(readback, written) is True

    @pytest.mark.parametrize(("readback", "written"), [
        # Reading a value as a number is LOSSY: it discards the currency code
        # and the leading zeros alike. Applying it to two strings would make a
        # colleague's edit indistinguishable from our own write.
        ("USD;100.00", "EUR;100.00"),
        ("0042", "42"),
        ("PO-0100", "PO-100"),
        # str(None) is "None"; a cleared field must not equal the literal text.
        (None, "None"),
        ("", None),
        (95000, 120000),
        ("Negotiation", "Closed Won"),
    ])
    def test_a_genuine_difference_is_never_read_as_the_same_value(
            self, readback, written):
        assert cp._same_value(readback, written) is False


class TestUpdateEarnsItsUndo:
    def test_patch_with_a_captured_record_is_reversible_and_restores_it(self):
        conn = FakeConnector(
            read=_sf_reads({"Amount": 100000, "StageName": "Prospect"},
                           {"Amount": 120000, "StageName": "Prospect"}),
            writes=["{}", "{}"])
        plan = cp.plan_write(conn, _patch(Amount=120000), capture=True)

        assert plan.reversible is True
        assert plan.restore.kind == "fields"
        assert plan.restore.captured is True
        # Prior values are held for exactly the fields being changed -- not the
        # whole record, which would replay non-writable system fields.
        assert plan.restore.prior == {"Amount": 100000}
        assert conn.reads == [{"path": SF_PATH, "params": SF_AMOUNT_QUERY}]
        assert plan.warnings == ()

        result = ea.run_saga(plan.steps)
        assert result.committed is True
        undo = plan.steps[0].undo
        assert undo is not None
        undo()
        assert conn.writes[-1] == {
            "op": "patch", "path": SF_PATH, "body": {"Amount": 100000}}

    def test_exposure_is_the_delta_not_the_new_value(self):
        # Moving an opportunity from $100k to $120k puts $20k at risk. The
        # captured restore point is what makes the true figure computable.
        conn = FakeConnector(read=_sf_record(Amount=100000))
        plan = cp.plan_write(conn, _patch(Amount=120000), capture=True)
        assert plan.preview.exposure_dollars == 20000.0

    def test_exposure_falls_back_to_the_whole_figure_without_a_prior_read(self):
        # Overstating exposure keeps a human in the loop; understating wouldn't.
        conn = FakeConnector(read="ERROR: 403 forbidden")
        plan = cp.plan_write(conn, _patch(Amount=120000), capture=True)
        assert plan.preview.exposure_dollars == 120000.0

    def test_non_money_fields_produce_no_exposure_figure(self):
        conn = FakeConnector(read=_sf_record(StageName="Prospect"))
        plan = cp.plan_write(conn, _patch(StageName="Closed Won"), capture=True)
        assert plan.preview.exposure_dollars is None
        assert plan.reversible is True

    def test_entities_name_the_record_touched(self):
        conn = FakeConnector(read=_sf_record(Amount=1))
        plan = cp.plan_write(conn, _patch(Amount=2), capture=True)
        assert plan.preview.entities == ("Opportunity/006xx0000000001AAA",)

    def test_servicenow_patch_earns_its_undo_through_the_result_envelope(self):
        conn = FakeConnector(name="servicenow", read=_sn_record(cost="USD;500.00"))
        plan = cp.plan_write(
            conn, {"op": "patch", "path": SN_PATH, "body": {"cost": "750.00"}},
            capture=True)
        assert plan.reversible is True
        assert plan.restore.prior == {"cost": "USD;500.00"}
        assert plan.preview.exposure_dollars == 250.0


class TestCaptureReadIsNarrowedAndRaw:
    """What the capture GET asks for decides whether the restore can restore."""

    def test_salesforce_reads_only_the_fields_being_changed_plus_the_stamp(self):
        # Reading the whole record and replaying it would clobber every field
        # the agent never touched. The stamp rides along to detect a race.
        conn = FakeConnector(read=_sf_record(Amount=1, StageName="Prospect"))
        cp.plan_write(conn, _patch(Amount=2, StageName="Closed Won"), capture=True)
        assert conn.reads == [{
            "path": SF_PATH,
            "params": {"fields": "Amount,StageName,LastModifiedDate"}}]

    def test_servicenow_capture_demands_raw_values_not_display_values(self):
        # A display-value read returns "New" for a choice field and a nested
        # object for a reference -- neither is writable back, so a restore built
        # on them would report success and change nothing.
        conn = FakeConnector(name="servicenow", read=_sn_record(cost="USD;5.00"))
        cp.plan_write(
            conn, {"op": "patch", "path": SN_PATH, "body": {"cost": "7.00"}},
            capture=True)
        assert conn.reads == [{"path": SN_PATH, "params": SN_COST_QUERY}]

    def test_a_delete_reads_the_whole_record_because_it_must_price_all_of_it(self):
        conn = FakeConnector(name="servicenow", read=_sn_record(cost="USD;5.00"))
        cp.plan_write(
            conn, {"op": "delete", "path": SN_PATH, "body": {}}, capture=True)
        assert "sysparm_fields" not in conn.reads[0]["params"]
        assert conn.reads[0]["params"]["sysparm_display_value"] == "false"


    def test_a_truncated_read_is_no_record_rather_than_the_record(self):
        envelope = json.dumps({"status_code": 200, "headers": {}, "truncated": True,
                               "response_chars": 9000, "preview": _sf_record(Amount=1_000_000)[:40]})
        conn = FakeConnector(read=envelope)
        plan = cp.plan_write(conn, {"op": "delete", "path": SF_PATH, "body": {}}, capture=True)
        assert "restore read returned no single record" in plan.warnings


class TestConcurrentEditsCannotBeSilentlyOverwritten:
    """A restore that overwrites somebody else's edit is not an undo."""

    def test_an_ordinary_undo_survives_our_own_writes_token_bump(self):
        # The regression that would have made the whole feature dead on arrival:
        # our own PATCH moves LastModifiedDate, so an undo compared against the
        # PLAN-time stamp would read "somebody edited this" every single time and
        # never restore anything. The reference is the stamp as of OUR write.
        conn = FakeConnector(read=_sf_reads({"Amount": 100000},
                                            {"Amount": 120000}),
                             writes=["{}", "{}"])
        plan = cp.plan_write(conn, _patch(Amount=120000), capture=True)
        assert plan.restore.token == SF_STAMP

        plan.steps[0].do()
        plan.steps[0].undo()
        assert [w["op"] for w in conn.writes] == ["patch", "patch"]
        assert conn.writes[-1]["body"] == {"Amount": 100000}

    def test_undo_refuses_when_the_record_moved_since_our_write(self):
        reads = _script(_sf_record(Amount=100000),
                        _sf_record(Amount=100000),
                        _sf_record(stamp=SF_AFTER, Amount=120000),
                        _sf_record(stamp="2026-07-02T09:30:00.000+0000",
                                   Amount=999999))
        conn = FakeConnector(read=reads, writes=["{}"])
        plan = cp.plan_write(conn, _patch(Amount=120000), capture=True)
        plan.steps[0].do()
        with pytest.raises(cp.PlanError, match="changed since the write"):
            plan.steps[0].undo()
        # The refusal happened BEFORE the restore write, not after it.
        assert [w["op"] for w in conn.writes] == ["patch"]
        assert conn.writes[-1]["body"] == {"Amount": 120000}

    def test_undo_refuses_when_the_record_cannot_be_re_read(self):
        reads = _script(_sf_record(Amount=100000),
                        _sf_record(Amount=100000),
                        _sf_record(stamp=SF_AFTER, Amount=120000),
                        "ERROR: rest (403): forbidden")
        conn = FakeConnector(read=reads, writes=["{}"])
        plan = cp.plan_write(conn, _patch(Amount=120000), capture=True)
        plan.steps[0].do()
        with pytest.raises(cp.PlanError, match="cannot confirm"):
            plan.steps[0].undo()
        assert len(conn.writes) == 1  # no blind restore

    def test_undo_refuses_when_our_own_writes_effect_was_never_observed(self):
        # The write went through but neither its echo nor the follow-up read
        # showed us the resulting token. With no honest reference point, the
        # undo refuses rather than restoring over an unknown state.
        reads = _script(_sf_record(Amount=100000), _sf_record(Amount=100000),
                        "ERROR: rest (503): gateway")
        conn = FakeConnector(read=reads, writes=["{}"])
        plan = cp.plan_write(conn, _patch(Amount=120000), capture=True)
        plan.steps[0].do()
        with pytest.raises(cp.PlanError, match="never observed"):
            plan.steps[0].undo()
        assert len(conn.writes) == 1

    def test_a_write_that_echoes_the_record_costs_no_extra_read(self):
        # ServiceNow returns the updated record from a PATCH, so the post-write
        # token arrives with the write itself: capture, pre-write re-check,
        # write, undo re-check. Salesforce answers 204 with an empty body and
        # has to spend a fourth read to see what its own write did.
        reads = _script(_sn_record(cost="100"), _sn_record(cost="100"),
                        _sn_record(mod_count="4", cost="250"))
        conn = FakeConnector(name="servicenow", read=reads,
                             writes=[_sn_record(mod_count="4", cost="250"), "{}"])
        plan = cp.plan_write(
            conn, {"op": "patch", "path": SN_PATH, "body": {"cost": "250"}},
            capture=True)
        plan.steps[0].do()
        plan.steps[0].undo()
        assert len(conn.reads) == 3
        assert conn.writes[-1]["body"] == {"cost": "100"}

    def test_a_read_without_the_token_earns_no_undo_at_all(self):
        # Field-level security can hide LastModifiedDate. Without it there is no
        # way to tell a genuine undo from clobbering a concurrent edit, so the
        # plan fails closed rather than promising a restore it cannot police.
        conn = FakeConnector(read=json.dumps(
            {"Id": "006xx0000000001AAA", "Amount": 100000}))
        plan = cp.plan_write(conn, _patch(Amount=120000), capture=True)
        assert plan.reversible is False
        assert plan.steps[0].undo is None
        assert any("LastModifiedDate" in w for w in plan.warnings)

    def test_a_json_null_token_counts_as_absent_not_as_the_text_None(self):
        # str(None) is truthy. If a null stamp stringified into the token slot
        # the emptiness check would pass and the undo would compare "None"
        # against a real stamp forever -- so nulls must read as absent.
        conn = FakeConnector(read=json.dumps(
            {"Id": "006xx0000000001AAA", "Amount": 100000,
             "LastModifiedDate": None}))
        plan = cp.plan_write(conn, _patch(Amount=120000), capture=True)
        assert plan.reversible is False
        assert plan.restore.token == ""

    def test_an_edit_while_the_card_awaited_approval_aborts_before_any_effect(self):
        # The window the post-write check cannot see: prior values are captured
        # at plan time, then a human sits with the card. If a colleague edits
        # the record during that wait, writing anyway and undoing later would
        # revert THEIR change to a value that went stale before the approval.
        # Nothing is sent at all.
        reads = _script(_sf_record(Amount=100000),
                        _sf_record(stamp="2026-07-01T13:00:00.000+0000",
                                   Amount=90000))
        conn = FakeConnector(read=reads, writes=["{}"])
        plan = cp.plan_write(conn, _patch(Amount=120000), capture=True)
        assert plan.reversible is True

        with pytest.raises(cp.PlanError, match="changed after the preview"):
            plan.steps[0].do()
        assert conn.writes == []

    def test_a_saga_rolls_back_clean_when_the_pre_write_check_aborts(self):
        reads = _script(_sf_record(Amount=100000),
                        _sf_record(stamp="2026-07-01T13:00:00.000+0000",
                                   Amount=90000))
        conn = FakeConnector(read=reads, writes=["{}"])
        plan = cp.plan_write(conn, _patch(Amount=120000), capture=True)
        result = ea.run_saga(plan.steps)
        assert result.committed is False
        # Nothing to compensate: the refusal landed before the write.
        assert conn.writes == []

    def test_a_post_write_read_showing_somebody_elses_value_refuses_the_undo(self):
        # Salesforce answers a PATCH with 204 and no body, so the reference
        # token comes from a second round trip -- which can return a record a
        # colleague has ALREADY moved past ours. Adopting their state as the
        # reference would license the undo to overwrite them, so a readback
        # that does not still carry what we wrote earns no reference at all.
        reads = _script(_sf_record(Amount=100000),
                        _sf_record(Amount=100000),
                        _sf_record(stamp=SF_AFTER, Amount=777777))
        conn = FakeConnector(read=reads, writes=["{}"])
        plan = cp.plan_write(conn, _patch(Amount=120000), capture=True)
        plan.steps[0].do()
        with pytest.raises(cp.PlanError, match="never observed"):
            plan.steps[0].undo()
        assert len(conn.writes) == 1  # no blind restore

    def test_a_readback_that_only_restates_our_value_differently_is_accepted(self):
        # These APIs stringify and re-type freely: an int goes out, "120000.0"
        # comes back. Treating that as a stranger's edit would refuse every
        # undo on a service that normalises, which is most of them.
        reads = _script(_sf_record(Amount=100000),
                        _sf_record(Amount=100000),
                        _sf_record(stamp=SF_AFTER, Amount="120000.0"),
                        _sf_record(stamp=SF_AFTER, Amount="120000.0"))
        conn = FakeConnector(read=reads, writes=["{}", "{}"])
        plan = cp.plan_write(conn, _patch(Amount=120000), capture=True)
        plan.steps[0].do()
        plan.steps[0].undo()
        assert conn.writes[-1]["body"] == {"Amount": 100000}

    def test_a_stranger_touching_a_field_we_never_wrote_does_not_block_the_undo(self):
        # Field level is the right granularity: our undo only ever replays the
        # fields we changed, so somebody else's edit to StageName is none of
        # our business and must not strand a restorable Amount.
        reads = _script(_sf_record(Amount=100000, StageName="Prospect"),
                        _sf_record(Amount=100000, StageName="Prospect"),
                        _sf_record(stamp=SF_AFTER, Amount=120000,
                                   StageName="Negotiation"),
                        _sf_record(stamp=SF_AFTER, Amount=120000,
                                   StageName="Negotiation"))
        conn = FakeConnector(read=reads, writes=["{}", "{}"])
        plan = cp.plan_write(conn, _patch(Amount=120000), capture=True)
        plan.steps[0].do()
        plan.steps[0].undo()
        assert conn.writes[-1]["body"] == {"Amount": 100000}

    def test_an_edit_sharing_our_writes_timestamp_still_refuses_the_undo(self):
        # Salesforce stamps LastModifiedDate to the SECOND -- the API always
        # answers .000 -- so a rep saving in the same second as our own write
        # carries a token identical to ours, and carries it forever however
        # long the undo is deferred. The token alone would wave that through
        # and destroy their edit. The values are the finer signal.
        reads = _script(_sf_record(Amount=100000),
                        _sf_record(Amount=100000),
                        _sf_record(stamp=SF_AFTER, Amount=120000),
                        # Same stamp, somebody else's number.
                        _sf_record(stamp=SF_AFTER, Amount=95000))
        conn = FakeConnector(read=reads, writes=["{}", "{}"])
        plan = cp.plan_write(conn, _patch(Amount=120000), capture=True)
        plan.steps[0].do()
        with pytest.raises(cp.PlanError, match="no longer hold what our write"):
            plan.steps[0].undo()
        # Refused BEFORE the restore PATCH: only our own write was ever sent.
        assert len(conn.writes) == 1

    def test_the_same_second_check_ignores_fields_the_restore_would_not_touch(self):
        # Same granularity principle as the post-write snapshot: we only refuse
        # over fields the restore would actually overwrite.
        reads = _script(_sf_record(Amount=100000, StageName="Prospect"),
                        _sf_record(Amount=100000, StageName="Prospect"),
                        _sf_record(stamp=SF_AFTER, Amount=120000,
                                   StageName="Negotiation"),
                        _sf_record(stamp=SF_AFTER, Amount=120000,
                                   StageName="Closed Won"))
        conn = FakeConnector(read=reads, writes=["{}", "{}"])
        plan = cp.plan_write(conn, _patch(Amount=120000), capture=True)
        plan.steps[0].do()
        plan.steps[0].undo()
        assert conn.writes[-1]["body"] == {"Amount": 100000}

    def test_a_reference_field_echoed_decorated_still_corroborates_our_write(
            self):
        # The shape asymmetry that would have made reference fields silently
        # irreversible: the capture GET asks for raw values
        # (sysparm_exclude_reference_link=true), but that is a READ parameter --
        # the echo of the write that SET the field comes back as
        # {"link": ..., "value": ...}. Compared raw, the record does not appear
        # to hold what we just wrote, the reference snapshot is forfeited, and
        # the undo the card promised refuses on every reference field.
        ref = {"link": "https://x.service-now.com/api/now/table/sys_user/u9",
               "value": "u9"}
        reads = _script(_sn_record(assigned_to="u1"),
                        _sn_record(assigned_to="u1"),
                        _sn_record(mod_count="4", assigned_to="u9"))
        conn = FakeConnector(
            name="servicenow", read=reads,
            writes=[_sn_record(mod_count="4", assigned_to=ref), "{}"])
        plan = cp.plan_write(
            conn, {"op": "patch", "path": SN_PATH,
                   "body": {"assigned_to": "u9"}}, capture=True)
        assert plan.reversible is True

        plan.steps[0].do()
        # The echo corroborated on its own: no fallback GET was needed.
        assert len(conn.reads) == 2
        plan.steps[0].undo()
        assert conn.writes[-1]["body"] == {"assigned_to": "u1"}

    def test_an_echo_that_does_not_show_our_write_falls_back_to_a_read(self):
        # The echo is an optimization, not the authority: it is whatever the
        # service volunteered, and may be truncated or shaped in a way this
        # dialect does not model. Believing it would forfeit a good undo over a
        # formatting difference, so an echo that does not visibly carry our
        # write is treated as no echo at all and the narrowed GET decides.
        reads = _script(_sn_record(cost="100"), _sn_record(cost="100"),
                        _sn_record(mod_count="4", cost="250"),
                        _sn_record(mod_count="4", cost="250"))
        conn = FakeConnector(
            name="servicenow", read=reads,
            # A token, but the cost field is missing from the echo entirely.
            writes=[_sn_record(mod_count="4"), "{}"])
        plan = cp.plan_write(
            conn, {"op": "patch", "path": SN_PATH, "body": {"cost": "250"}},
            capture=True)
        plan.steps[0].do()
        assert len(conn.reads) == 3  # capture, pre-write, fallback
        plan.steps[0].undo()
        assert conn.writes[-1]["body"] == {"cost": "100"}

    def test_every_field_the_write_touched_must_corroborate_not_just_one(self):
        # The snapshot is the undo's whole reference, and the undo replays every
        # field in the body. One field agreeing while another has already moved
        # means the record is not our write's effect, so adopting it would let
        # the restore overwrite the field that moved.
        reads = _script(
            _sf_record(Amount=100000, StageName="Prospect"),
            _sf_record(Amount=100000, StageName="Prospect"),
            # Amount is ours; StageName is somebody's, already past our write.
            _sf_record(stamp=SF_AFTER, Amount=120000, StageName="Closed Lost"))
        conn = FakeConnector(read=reads, writes=["{}"])
        plan = cp.plan_write(
            conn, _patch(Amount=120000, StageName="Closed Won"), capture=True)
        plan.steps[0].do()
        with pytest.raises(cp.PlanError, match="never observed"):
            plan.steps[0].undo()
        assert len(conn.writes) == 1  # no partial, no blind restore

    def test_a_readback_restating_our_value_differently_does_not_block_restore(self):
        # The undo's value check is the same tolerant comparison the do-step
        # uses, so a service answering "120000" for the integer we sent must
        # not be read as a stranger's edit and strand a restorable record.
        reads = _script(_sf_record(Amount=100000),
                        _sf_record(Amount=100000),
                        _sf_record(stamp=SF_AFTER, Amount=120000),
                        _sf_record(stamp=SF_AFTER, Amount="120000.00"))
        conn = FakeConnector(read=reads, writes=["{}", "{}"])
        plan = cp.plan_write(conn, _patch(Amount=120000), capture=True)
        plan.steps[0].do()
        plan.steps[0].undo()
        assert conn.writes[-1]["body"] == {"Amount": 100000}


class TestTheApprovedWriteIsTheExecutedWrite:
    """The card prices one write; the do-step must not send a different one."""

    def test_mutating_the_caller_dict_after_planning_changes_nothing(self):
        # An agent that keeps its params dict and edits it while the card waits
        # for approval would otherwise move $4.9M on an action a human approved
        # at $20k, and change a field the restore point never captured.
        params = _patch(Amount=120000)
        conn = FakeConnector(read=_sf_reads({"Amount": 100000},
                                            {"Amount": 120000}),
                             writes=["{}", "{}"])
        plan = cp.plan_write(conn, params, capture=True)
        digest = plan.preview.params_sha256

        params["body"]["Amount"] = 5000000
        params["body"]["StageName"] = "Closed Won"

        plan.steps[0].do()
        assert conn.writes[-1]["body"] == {"Amount": 120000}
        assert plan.preview.params_sha256 == digest
        assert plan.preview.exposure_dollars == 20000.0

    def test_a_value_that_cannot_be_deep_copied_still_gets_its_body_detached(
            self):
        # deepcopy is the snapshot's first choice, but the params come from an
        # agent and can carry anything. Falling back to nothing would hand the
        # do-step the caller's own dict back; the one-level copy still detaches
        # the body, which is the mutation that changes what executes.
        class Exotic:
            def __deepcopy__(self, memo):
                raise TypeError("not copyable")

        params = {"op": "patch", "path": SF_PATH,
                  "body": {"Amount": 120000}, "client": Exotic()}
        snap = cp._snapshot(params)
        params["body"]["Amount"] = 5000000
        assert snap["body"] == {"Amount": 120000}
        assert isinstance(snap["client"], Exotic)  # passed through, not dropped


class TestMalformedPathsRefuseRatherThanRaise:
    """Planning promises never to raise; the path comes from an agent."""

    @pytest.mark.parametrize("path", ["https://[evil", "//[x", "https://h]/x"])
    @pytest.mark.parametrize("op", ["patch", "put", "delete", "post"])
    def test_an_unparseable_url_yields_a_refusing_plan(self, path, op):
        # urlsplit raises "Invalid IPv6 URL" on an unbalanced bracket. A
        # traceback out of plan_write would crash the agent loop and the
        # `maverick connectors plan` CLI instead of routing to a human.
        conn = FakeConnector(read=_sf_record(Amount=1))
        plan = cp.plan_write(
            conn, {"op": op, "path": path, "body": {"Amount": 2}}, capture=True)
        assert plan.reversible is False
        assert plan.steps[0].undo is None


class TestAQueryStringOnTheWritePathForfeitsTheInverse:
    def test_a_decorated_servicenow_patch_earns_no_undo(self):
        # sysparm_input_display_value=true makes the API read submitted values
        # as display LABELS. The undo re-sends this same path, so replaying a
        # raw captured prior through it writes a different value than the one
        # captured -- a restore that silently does not restore.
        conn = FakeConnector(name="servicenow", read=_sn_record(cost="100"))
        plan = cp.plan_write(
            conn, {"op": "patch",
                   "path": f"{SN_PATH}?sysparm_input_display_value=true",
                   "body": {"cost": "250"}}, capture=True)
        assert plan.reversible is False
        assert plan.steps[0].undo is None
        assert any("query string" in w for w in plan.warnings)

    def test_a_decorated_servicenow_put_earns_no_undo_either(self):
        # PUT merges on this API, so it is normally reversible -- which is
        # exactly why the forfeit has to be checked before the verb rather than
        # inside the PATCH branch alone.
        conn = FakeConnector(name="servicenow", read=_sn_record(cost="100"))
        plan = cp.plan_write(
            conn, {"op": "put",
                   "path": f"{SN_PATH}?sysparm_input_display_value=true",
                   "body": {"cost": "250"}}, capture=True)
        assert plan.reversible is False
        assert any("query string" in w for w in plan.warnings)

    def test_the_capture_read_still_happens_so_exposure_is_still_priced(self):
        # Forfeiting the inverse must not also blind the card: a human deciding
        # this one still needs to see the dollars.
        conn = FakeConnector(name="servicenow", read=_sn_record(cost="100"))
        plan = cp.plan_write(
            conn, {"op": "patch", "path": f"{SN_PATH}?sysparm_fields=cost",
                   "body": {"cost": "250"}}, capture=True)
        assert plan.reversible is False
        assert plan.preview.exposure_dollars == 150.0


class TestUpdateFailsClosed:
    def test_a_system_managed_field_earns_no_inverse(self):
        # ExpectedRevenue is Amount x Probability -- a formula. Its prior value
        # reads back perfectly and then silently fails to apply, so a restore
        # built on it would report success while changing nothing.
        conn = FakeConnector(read=_sf_record(ExpectedRevenue=50000))
        plan = cp.plan_write(conn, _patch(ExpectedRevenue=60000), capture=True)
        assert plan.reversible is False
        assert plan.steps[0].undo is None
        assert any("system-managed" in w for w in plan.warnings)

    def test_writing_an_audit_stamp_also_fails_closed(self):
        conn = FakeConnector(read=_sf_record(Amount=1))
        plan = cp.plan_write(conn, _patch(CreatedDate="2020-01-01"), capture=True)
        assert plan.reversible is False

    def test_servicenow_auto_number_is_unrestorable(self):
        conn = FakeConnector(name="servicenow", read=_sn_record(number="INC0001"))
        plan = cp.plan_write(
            conn, {"op": "patch", "path": SN_PATH, "body": {"number": "INC9999"}},
            capture=True)
        assert plan.reversible is False
        assert any("system-managed" in w for w in plan.warnings)

    def test_a_failed_restore_read_makes_the_write_irreversible(self):
        conn = FakeConnector(read="ERROR: rest (403): upstream request failed")
        plan = cp.plan_write(conn, _patch(Amount=120000), capture=True)
        assert plan.reversible is False
        assert plan.steps[0].undo is None
        assert plan.restore.kind == "none"
        assert any("restore read failed" in w for w in plan.warnings)

    def test_a_field_missing_from_the_read_blocks_a_partial_restore(self):
        # Field-level read permission can hide a field we are about to change.
        # Restoring the others is not an inverse -- it would leave that field
        # changed forever, so the whole plan fails closed.
        conn = FakeConnector(read=_sf_record(Amount=100000))
        plan = cp.plan_write(
            conn, _patch(Amount=120000, Description="new"), capture=True)
        assert plan.reversible is False
        assert any("Description" in w for w in plan.warnings)

    def test_a_read_that_raises_is_absorbed_not_propagated(self):
        def _boom():
            raise RuntimeError("socket died")

        conn = FakeConnector(read=_boom)
        plan = cp.plan_write(conn, _patch(Amount=1), capture=True)
        assert plan.reversible is False
        assert any("RuntimeError" in w for w in plan.warnings)

    def test_a_non_record_path_is_never_read_and_never_reversible(self):
        conn = FakeConnector()
        plan = cp.plan_write(conn, _patch("/services/data/v60.0/query", Amount=1),
                             capture=True)
        assert conn.reads == []  # nothing to read; don't guess at a URL
        assert plan.reversible is False
        assert any("does not address a single" in w for w in plan.warnings)

    def test_disabling_restore_reads_makes_updates_irreversible_with_no_get(self):
        conn = FakeConnector(read=_sf_record(Amount=100000))
        plan = cp.plan_write(conn, _patch(Amount=120000), capture=False)
        assert conn.reads == []
        assert plan.reversible is False
        assert any("restore_points" in w for w in plan.warnings)

    def test_unknown_connector_earns_nothing(self):
        conn = FakeConnector(name="workday", read=_sf_record(Amount=100000))
        plan = cp.plan_write(conn, _patch(Amount=120000), capture=True)
        assert conn.reads == []
        assert plan.reversible is False


class TestCreateAndDestroy:
    def test_post_is_reversible_by_deleting_the_id_the_create_returns(self):
        conn = FakeConnector(writes=[
            json.dumps({"id": "006NEW000000001AAA", "success": True}), "{}"])
        plan = cp.plan_write(
            conn, {"op": "post", "path": SF_COLLECTION,
                   "body": {"Name": "Acme", "Amount": 90000}}, capture=True)
        assert conn.reads == []  # nothing exists yet to read
        assert plan.reversible is True
        assert plan.restore.kind == "created"
        # The id doesn't exist at plan time -- that's why captured is False.
        assert plan.restore.captured is False
        assert plan.preview.exposure_dollars == 90000.0

        plan.steps[0].do()
        plan.steps[0].undo()
        assert conn.writes[-1] == {
            "op": "delete", "path": f"{SF_COLLECTION}/006NEW000000001AAA",
            "body": {}}

    def test_a_post_to_an_unmodelled_connector_earns_no_inverse(self):
        # The generic dialect knows no vendor's URL grammar. Appending the new
        # id to an unmodelled path is a guess, and a guess that resolves to
        # some OTHER endpoint turns a compensation into an unrelated
        # destructive write. The module says an unknown connector earns no
        # reversibility; POST is not an exception to that.
        conn = FakeConnector(name="workday", writes=['{"id": "x1"}'])
        plan = cp.plan_write(
            conn, {"op": "post", "path": "/v1/payments",
                   "body": {"amount": 90000}}, capture=True)
        assert plan.reversible is False
        assert plan.steps[0].undo is None
        assert any("collection" in w for w in plan.warnings)

    def test_a_post_to_an_rpc_endpoint_earns_no_inverse(self):
        # A POST is not synonymous with a create. This one sends an email, and
        # no DELETE unsends it -- so the card must not advertise it reversible
        # and let the autonomy dial book it as a safely-undoable action.
        conn = FakeConnector(writes=['[{"isSuccess": true}]'])
        plan = cp.plan_write(
            conn, {"op": "post",
                   "path": "/services/data/v60.0/actions/standard/emailSimple",
                   "body": {"inputs": [{"emailBody": "hi"}]}}, capture=True)
        assert plan.reversible is False
        assert plan.steps[0].undo is None

    def test_a_query_string_on_a_create_path_earns_no_inverse_either(self):
        # A create's whole inverse rests on the id coming back in the response,
        # and the parameters that reshape a write reshape what it answers with:
        # sysparm_fields prunes the echo, sysparm_display_value=all re-types it.
        # An inverse whose evidence may never arrive is not an inverse -- and
        # promising one costs more than refusing, because the undo would fail
        # only after the record already exists.
        conn = FakeConnector(name="servicenow", writes=[
            json.dumps({"result": {"sys_id": "f" * 32}})])
        plan = cp.plan_write(
            conn, {"op": "post",
                   "path": "/api/now/table/incident?sysparm_input_display_value=true",
                   "body": {"short_description": "printer down"}}, capture=True)
        assert plan.reversible is False
        assert plan.steps[0].undo is None
        assert any("query string" in w for w in plan.warnings)

    def test_the_delete_target_is_built_from_the_path_component(self):
        # Belt to the forfeit's braces, asserted where the concatenation
        # actually lives: appending the id to a raw path would build
        # ".../incident?sysparm_x=1/<sys_id>", landing the id inside the QUERY
        # so the compensation addresses the table rather than the new record.
        new_id = "f" * 32
        conn = FakeConnector(name="servicenow", writes=["{}"])
        _restore, undo, _warn = cp._inverse_for_create(
            conn, cp.dialect_for("servicenow"),
            "/api/now/table/incident?sysparm_input_display_value=true",
            [json.dumps({"result": {"sys_id": new_id}})])
        assert undo is not None
        undo()
        assert conn.writes[-1] == {
            "op": "delete", "path": f"/api/now/table/incident/{new_id}",
            "body": {}}

    def test_an_id_that_is_not_an_id_never_reaches_the_delete_address(self):
        # The delete address is built by concatenating a value the SERVICE
        # chose. A response carrying traversal, a query string, or simply
        # something the wrong shape would aim the compensation at an endpoint
        # nobody approved -- so the id must look like this vendor's before it is
        # allowed into a URL, and the undo fails loudly when it does not.
        for bogus in ("../../../services/data/v60.0/sobjects/Account/001xx0",
                      "006xx0000000001AAA?cascade=true", "006xx", "a" * 40):
            conn = FakeConnector(writes=[json.dumps({"id": bogus})])
            plan = cp.plan_write(
                conn, {"op": "post", "path": SF_COLLECTION,
                       "body": {"Name": "Acme"}}, capture=True)
            plan.steps[0].do()
            with pytest.raises(cp.PlanError, match="not a salesforce record id"):
                plan.steps[0].undo()
            assert [w["op"] for w in conn.writes] == ["post"]  # no blind delete

    def test_the_card_names_the_create_target_the_way_the_restore_point_does(
            self):
        # A create addresses a collection, so the path names no record. If the
        # card fell back to the raw path while the restore point said
        # "Opportunity/(new)", one write would be described two ways and an
        # operator reconciling the record would be reading about two.
        conn = FakeConnector(writes=[json.dumps({"id": "006NEW000000001AAA"})])
        plan = cp.plan_write(
            conn, {"op": "post", "path": SF_COLLECTION, "body": {"Name": "A"}},
            capture=True)
        assert plan.restore.entity == "Opportunity/(new)"
        assert plan.preview.entities == ("Opportunity/(new)",)

    def test_undo_before_the_create_ran_raises_rather_than_no_opping(self):
        plan = cp.plan_write(
            FakeConnector(), {"op": "post", "path": SF_COLLECTION,
                              "body": {"Name": "Acme"}}, capture=True)
        with pytest.raises(cp.PlanError, match="never reported a response"):
            plan.steps[0].undo()

    def test_undo_raises_loudly_when_the_create_hid_the_id(self):
        # A silent no-op undo is worse than a failed one: the saga would report
        # a clean rollback while the record still exists.
        conn = FakeConnector(writes=[json.dumps({"success": True})])
        plan = cp.plan_write(
            conn, {"op": "post", "path": SF_COLLECTION, "body": {"Name": "A"}},
            capture=True)
        plan.steps[0].do()
        with pytest.raises(cp.PlanError, match="no record id"):
            plan.steps[0].undo()

    def test_put_is_irreversible_because_system_fields_are_not_writable(self):
        conn = FakeConnector(read=_sf_record(Amount=100000))
        plan = cp.plan_write(
            conn, {"op": "put", "path": SF_PATH, "body": {"Amount": 120000}},
            capture=True)
        assert plan.reversible is False
        assert any("non-writable system fields" in w for w in plan.warnings)

    def test_servicenow_put_is_reversible_because_it_merges_like_patch(self):
        # The Table API's PUT does NOT null omitted fields -- it behaves exactly
        # like PATCH. Calling it a full replace here would refuse a write that
        # is genuinely restorable and stall the autonomy dial on a false
        # negative; the vendor fact belongs in the dialect, not in the verb.
        reads = _script(_sn_record(cost="USD;500.00"),
                        _sn_record(cost="USD;500.00"),
                        _sn_record(mod_count="4", cost="750.00"))
        conn = FakeConnector(name="servicenow", read=reads,
                             writes=[_sn_record(mod_count="4", cost="750.00"),
                                     "{}"])
        plan = cp.plan_write(
            conn, {"op": "put", "path": SN_PATH, "body": {"cost": "750.00"}},
            capture=True)
        assert plan.reversible is True
        assert plan.restore.prior == {"cost": "USD;500.00"}
        plan.steps[0].do()
        plan.steps[0].undo()
        # The restore goes back as a PATCH -- the minimal, field-scoped inverse.
        assert conn.writes[-1] == {
            "op": "patch", "path": SN_PATH, "body": {"cost": "USD;500.00"}}

    def test_delete_is_irreversible_and_prices_the_record_it_destroys(self):
        conn = FakeConnector(read=_sf_record(Amount=250000))
        plan = cp.plan_write(
            conn, {"op": "delete", "path": SF_PATH, "body": {}}, capture=True)
        assert plan.reversible is False
        assert any("new id" in w for w in plan.warnings)
        # The read still happened -- to price what is about to be destroyed.
        assert plan.preview.exposure_dollars == 250000.0


class TestErrorStringsBecomeFailures:
    """The load-bearing adapter: connectors *return* errors, sagas need raises."""

    def test_a_write_that_returns_an_error_string_raises(self):
        conn = FakeConnector(read=_sf_record(Amount=1),
                             writes=["ERROR: salesforce (500): upstream failed"])
        plan = cp.plan_write(conn, _patch(Amount=2), capture=True)
        with pytest.raises(cp.PlanError, match="500"):
            plan.steps[0].do()

    def test_a_failed_write_rolls_the_saga_back_instead_of_committing(self):
        # Without the ERROR->raise adapter, run_saga would book this rejected
        # write as committed and never compensate.
        conn = FakeConnector(read=_sf_record(Amount=1),
                             writes=["ERROR: salesforce (500): upstream failed"])
        plan = cp.plan_write(conn, _patch(Amount=2), capture=True)
        result = ea.run_saga(plan.steps)
        assert result.committed is False
        assert result.results[0].ok is False

    def test_a_failed_restore_write_is_reported_as_a_failed_undo(self):
        conn = FakeConnector(read=_sf_reads({"Amount": 1}, {"Amount": 2}),
                             writes=["{}", "ERROR: salesforce (409): conflict"])
        plan = cp.plan_write(conn, _patch(Amount=2), capture=True)
        plan.steps[0].do()
        with pytest.raises(cp.PlanError, match="409"):
            plan.steps[0].undo()


class TestRefusedPlans:
    def test_an_invalid_op_yields_a_plan_with_no_steps(self):
        plan = cp.plan_write(FakeConnector(), {"op": "get", "path": SF_PATH})
        assert plan.steps == ()
        assert plan.reversible is False
        assert plan.preview.predicted_outcome == 0.0
        assert "op must be" in plan.preview.effect

    def test_a_missing_path_is_refused_before_any_io(self):
        conn = FakeConnector()
        plan = cp.plan_write(conn, {"op": "patch", "path": "", "body": {}})
        assert plan.steps == ()
        assert conn.reads == [] and conn.writes == []

    def test_a_connector_whose_preview_explodes_never_propagates(self):
        class Exploding(FakeConnector):
            def preview_write(self, params):
                raise ValueError("bad connector")

        plan = cp.plan_write(Exploding(), _patch(Amount=1))
        assert plan.steps == ()
        assert "ValueError" in plan.preview.effect


class TestPreviewContent:
    def test_the_effect_is_the_connectors_own_no_network_sentence(self):
        # preview_write stays the single source of the human sentence and of
        # op/path validation; plan_write adds structure around it.
        conn = FakeConnector(read=_sf_record(Amount=1))
        plan = cp.plan_write(conn, _patch(Amount=2), capture=True)
        assert plan.preview.effect.startswith("would PATCH salesforce")
        assert "Amount" in plan.preview.effect

    def test_params_digest_commits_to_the_params_without_storing_them(self):
        params = _patch(Amount=120000)
        digest = cp.params_digest(params)
        assert len(digest) == 64
        assert cp.params_digest(dict(reversed(list(params.items())))) == digest
        assert cp.params_digest(_patch(Amount=1)) != digest

    def test_card_view_omits_raw_params_and_keeps_the_structure(self):
        conn = FakeConnector(read=_sf_record(Amount=100000))
        view = cp.plan_write(conn, _patch(Amount=120000), capture=True
                             ).preview.card_view()
        assert view["exposure_dollars"] == 20000.0
        assert view["reversible"] is True
        assert view["entities"] == ["Opportunity/006xx0000000001AAA"]
        assert "params_sha256" not in view and "body" not in view

    def test_an_irreversible_plan_predicts_more_humbly_than_a_reversible_one(self):
        record = _sf_record(Amount=100000)
        reversible = cp.plan_write(
            FakeConnector(read=record), _patch(Amount=1), capture=True)
        blind = cp.plan_write(
            FakeConnector(read=record), _patch(Amount=1), capture=False)
        assert blind.preview.predicted_outcome < reversible.preview.predicted_outcome

    def test_an_explicit_prediction_overrides_the_structural_prior(self):
        conn = FakeConnector(read=_sf_record(Amount=1))
        plan = cp.plan_write(conn, _patch(Amount=2), capture=True, predicted=0.42)
        assert plan.preview.predicted_outcome == 0.42


class TestShadowModeIntegration:
    """The point of the whole module: these plans drive Shadow Mode."""

    @pytest.fixture(autouse=True)
    def _on(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_EARNED_AUTONOMY", "1")

    def _engine(self, tmp_path):
        return ea.EarnedAutonomyEngine(
            cards=ea.CardStore(path=tmp_path / "cards.ndjson"),
            ledger=ea.TrustLedger(path=tmp_path / "trust.ndjson"),
            frozen_fn=lambda: False, audit_fn=lambda kind, **p: None,
            now=lambda: 100.0)

    def test_a_reversible_plan_executes_under_human_approval(self, tmp_path):
        conn = FakeConnector(read=_sf_record(Amount=100000), writes=["{}"])
        plan = cp.plan_write(conn, _patch(Amount=120000), capture=True)
        out = ea.shadow_execute(
            plan.preview, plan.steps, principal="alice", goal_id=1,
            episode_id=1, approve=lambda card: True,
            engine=self._engine(tmp_path))
        assert out.executed is True and out.committed is True
        assert conn.writes[-1]["body"] == {"Amount": 120000}

    def test_an_unearned_undo_refuses_before_any_effect(self, tmp_path):
        conn = FakeConnector(read="ERROR: 403 forbidden")
        plan = cp.plan_write(conn, _patch(Amount=120000), capture=True)
        out = ea.shadow_execute(
            plan.preview, plan.steps, principal="alice", goal_id=1,
            episode_id=1, approve=lambda card: True,
            engine=self._engine(tmp_path))
        assert out.committed is False
        assert conn.writes == []  # refused BEFORE touching the system of record

    def test_the_approver_sees_the_dollars_and_the_reversibility(self, tmp_path):
        seen: list[dict] = []
        conn = FakeConnector(read=_sf_record(Amount=100000), writes=["{}"])
        plan = cp.plan_write(conn, _patch(Amount=350000), capture=True)
        ea.shadow_execute(
            plan.preview, plan.steps, principal="alice", goal_id=1,
            episode_id=1, approve=lambda card: bool(seen.append(card)) or True,
            engine=self._engine(tmp_path))
        assert seen[0]["exposure_dollars"] == 250000.0
        assert seen[0]["reversible"] is True


class TestConfigKnob:
    def test_restore_points_default_on_so_autonomy_can_be_earned(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_GOVERNED_RESTORE_POINTS", raising=False)
        import maverick.config as config
        monkeypatch.setattr(config, "load_config", dict)
        assert config.get_governed_connectors()["restore_points"] is True

    def test_env_override_turns_restore_reads_off(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_GOVERNED_RESTORE_POINTS", "0")
        import maverick.config as config
        monkeypatch.setattr(
            config, "load_config", lambda: {"governed_connectors":
                                            {"restore_points": True}})
        assert config.get_governed_connectors()["restore_points"] is False
        assert cp.restore_points_enabled() is False

    def test_unreadable_config_disables_the_read_rather_than_defaulting_on(
            self, monkeypatch):
        import maverick.config as config

        def _boom():
            raise OSError("config gone")

        monkeypatch.setattr(config, "get_governed_connectors", _boom)
        assert cp.restore_points_enabled() is False
