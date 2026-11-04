"""Client regressions discovered outside the existing happy-path tests.

All external responses are synthetic; filesystem and persistence effects are real.
"""
from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from contextlib import closing, contextmanager
from types import SimpleNamespace

import httpx
import pytest
from maverick import shoring
from maverick.file_lock import cross_process_lock
from maverick.tools import _rest_connector, _ssrf, pdf_reader, spreadsheet


def _rest(monkeypatch, response):
    monkeypatch.setenv("CLIENT_AUDIT_BASE_URL", "https://example.test")
    monkeypatch.setenv("CLIENT_AUDIT_TOKEN", "synthetic-connector-token")

    @contextmanager
    def client(*args, **kwargs):
        @contextmanager
        def stream(*a, **kw):
            with closing(httpx.Response(response.status_code, headers=response.headers,
                                        stream=httpx.ByteStream(response.content))) as streamed:
                yield streamed
        yield SimpleNamespace(stream=stream)

    monkeypatch.setattr(_ssrf, "safe_client", client)
    return _rest_connector.make_rest_tool(
        name="client_audit", base_url_env="CLIENT_AUDIT_BASE_URL",
        token_env="CLIENT_AUDIT_TOKEN", description="Synthetic response fixture",
    )


def test_rest_large_response_is_valid_json_with_explicit_incompleteness(monkeypatch):
    tool = _rest(monkeypatch, httpx.Response(200, json={"items": ["x" * 6000]}))
    result = json.loads(tool.fn({"op": "get", "path": "/orders"}))
    assert result["truncated"] is True
    assert result["status_code"] == 200
    assert "preview" in result


def test_rest_metadata_exposes_revision_without_cookies_or_arbitrary_headers(monkeypatch):
    response = httpx.Response(200, json={"id": "order-7"}, headers={
        "ETag": '"revision-7"', "Set-Cookie": "session=private",
        "Authorization": "reflected-private-credential",
    })
    tool = _rest(monkeypatch, response)
    result = json.loads(tool.fn({
        "op": "get", "path": "/orders/7", "response_format": "metadata",
    }))
    assert result["status_code"] == 200
    assert result["headers"] == {"etag": '"revision-7"'}
    assert result["body"] == {"id": "order-7"}
    assert "private" not in json.dumps(result)


def test_rest_redirect_is_not_reported_as_completed_work(monkeypatch):
    tool = _rest(monkeypatch, httpx.Response(302, headers={"Location": "https://other.test"}))
    result = tool.fn({"op": "get", "path": "/orders"})
    assert result.startswith("ERROR:") and "302" in result


def test_rest_accepted_job_remains_visibly_pending(monkeypatch):
    tool = _rest(monkeypatch, httpx.Response(202, json={"job": "pending-job"}))
    result = json.loads(tool.fn({"op": "post", "path": "/jobs", "confirm": True}))
    assert result["status_code"] == 202
    assert result["pending"] is True


@pytest.mark.parametrize("limit", ["garbage", {}, [], True, -1, 10001])
def test_spreadsheet_invalid_limit_is_a_tool_error(tmp_path, limit):
    path = tmp_path / "orders.csv"
    path.write_text("order,quantity\n0007,500\n", encoding="utf-8")
    result = spreadsheet._run({"op": "read", "path": str(path), "limit": limit})
    assert result.startswith("ERROR:") and "limit" in result


def test_spreadsheet_rejects_row_strings_without_changing_existing_file(tmp_path):
    path = tmp_path / "orders.csv"
    original = b"order,quantity\n0007,500\n"
    path.write_bytes(original)
    result = spreadsheet._run({"op": "write", "path": str(path), "rows": ["750"]})
    assert result.startswith("ERROR:")
    assert path.read_bytes() == original


def test_spreadsheet_csv_bom_does_not_change_first_column_name(tmp_path):
    path = tmp_path / "orders.csv"
    path.write_text("order,quantity\n0007,500\n", encoding="utf-8-sig")
    result = json.loads(spreadsheet._run({"op": "read", "path": str(path)}))
    assert result == [["order", "quantity"], ["0007", "500"]]


def test_spreadsheet_info_does_not_report_a_truncated_count_as_exact(tmp_path):
    path = tmp_path / "orders.csv"
    path.write_text("order,quantity\n" + "0007,500\n" * 10000, encoding="utf-8")
    result = spreadsheet._run({"op": "info", "path": str(path)})
    assert "rows=10001" in result or "at least" in result.lower()


def test_spreadsheet_failed_write_preserves_original(tmp_path, monkeypatch):
    path = tmp_path / "orders.csv"
    original = b"order,quantity\n0007,500\n"
    path.write_bytes(original)

    def writer(stream):
        def fail(rows):
            stream.write("partial output")
            raise OSError("synthetic full disk")
        return SimpleNamespace(writerows=fail)

    monkeypatch.setattr(spreadsheet._csv, "writer", writer)
    result = spreadsheet._run({"op": "write", "path": str(path), "rows": [[750]]})
    assert result.startswith("ERROR:")
    assert path.read_bytes() == original
    assert sorted(p.name for p in tmp_path.iterdir()) == ["orders.csv", "orders.csv.lock"]


def test_spreadsheet_macro_enabled_edits_are_refused_before_loading(tmp_path, monkeypatch):
    path = tmp_path / "customer.xlsm"
    original = b"synthetic macro-enabled original; do not parse"
    path.write_bytes(original)
    monkeypatch.setattr(spreadsheet, "_openpyxl", lambda: pytest.fail("must not strip macros"))
    for op, fields in (("write", {"rows": [[1]]}), ("set_cell", {"cell": "A1", "value": 1})):
        result = spreadsheet._run({"op": op, "path": str(path), **fields})
        assert result.startswith("ERROR:") and "xlsm" in result.lower()
        assert path.read_bytes() == original


def test_pdf_uses_assigned_workspace_instead_of_server_cwd(tmp_path, monkeypatch):
    workspace = tmp_path / "assigned"
    workspace.mkdir()
    (workspace / "proof.pdf").write_bytes(b"synthetic proof")
    process = tmp_path / "server"
    process.mkdir()
    monkeypatch.chdir(process)
    monkeypatch.setattr("maverick.parser_isolation.should_isolate", lambda: False)
    monkeypatch.setattr(pdf_reader, "extract_text_from_bytes", lambda data, **kw: data.decode())
    tool = pdf_reader.read_pdf(SimpleNamespace(workdir=workspace))
    assert tool.fn({"source": "proof.pdf"}) == "synthetic proof"
    (process / "private.pdf").write_bytes(b"different workspace")
    assert tool.fn({"source": str(process / "private.pdf")}).startswith("ERROR:")


@pytest.mark.parametrize("arguments", [{"source": 7}, {"source": "x.pdf", "max_chars": "invalid"}])
def test_pdf_malformed_arguments_do_not_escape_tool(arguments):
    assert pdf_reader._run_read_pdf(arguments).startswith("ERROR:")


def test_pdf_corrupt_input_is_a_tool_error_when_isolation_is_off(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "bad.pdf").write_bytes(b"synthetic invalid PDF")
    monkeypatch.setattr("maverick.parser_isolation.should_isolate", lambda: False)

    def fail(*args, **kwargs):
        raise ValueError("synthetic damaged PDF")

    monkeypatch.setattr(pdf_reader, "extract_text_from_bytes", fail)
    assert pdf_reader._run_read_pdf({"source": "bad.pdf"}).startswith("ERROR:")


def test_shoring_capacity_refuses_new_function_without_silent_data_loss(monkeypatch):
    monkeypatch.setattr(shoring, "_MAX_FUNCTIONS", 2)
    shoring.upsert(shoring.Function("one", "First"))
    shoring.upsert(shoring.Function("two", "Second"))
    original = shoring._book_path().read_bytes()
    with pytest.raises(ValueError, match="capacity|limit|maximum"):
        shoring.upsert(shoring.Function("three", "Third"))
    assert shoring._book_path().read_bytes() == original
    shoring.upsert(shoring.Function("one", "Updated"))
    assert {f.key: f.name for f in shoring.load()} == {"one": "Updated", "two": "Second"}


def test_shoring_corrupt_book_cannot_be_overwritten_by_an_edit():
    path = shoring._book_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    original = b'{"damaged":'
    path.write_bytes(original)
    with pytest.raises((ValueError, RuntimeError, OSError)):
        shoring.upsert(shoring.Function("new", "New"))
    assert path.read_bytes() == original


def test_shoring_writer_waits_for_shared_book_lock():
    path = shoring._book_path()
    entered, finished = threading.Event(), threading.Event()

    def write():
        entered.set()
        shoring.upsert(shoring.Function("one", "First"))
        finished.set()

    with ThreadPoolExecutor(max_workers=1) as pool:
        with cross_process_lock(path, strict=True):
            future = pool.submit(write)
            assert entered.wait(5)
            assert not finished.wait(0.2), "writer ignored another transaction's lock"
        future.result(timeout=10)
    assert [f.key for f in shoring.load()] == ["one"]


def test_shoring_empty_throughput_is_unmeasured():
    world = SimpleNamespace(
        list_goals=lambda **kw: [], list_episodes=lambda **kw: [],
        list_approvals=lambda **kw: [],
    )
    function = shoring.Function("ap", "AP", department="finance_ap", slas=[
        shoring.SLATarget("Throughput", "throughput_per_day", 5),
    ])
    [status] = shoring.sla_status(function, world)
    assert status["status"] == "no_data" and status["actual"] is None


@pytest.mark.parametrize("body", [[], "{bad", None])
def test_rest_malformed_write_body_refuses_before_network(monkeypatch, body):
    tool = _rest(monkeypatch, httpx.Response(200, json={"ok": True}))
    assert tool.fn({"op": "post", "path": "/orders", "body": body, "confirm": True}).startswith("ERROR:")


@pytest.mark.parametrize("payload", ["x" * 5000, "\"\\\n" * 2500, "\u2603" * 3000], ids=["ascii", "escaping", "unicode"])
def test_response_encoding_bound_is_valid_with_escaped_content(payload):
    response = httpx.Response(202, headers={
        "etag": "e" * 512, "last-modified": "m" * 512, "retry-after": "r" * 512,
    })
    rendered = _rest_connector._rest_response(response, payload, {}, "token")
    assert len(rendered) <= 4000
    result = json.loads(rendered)
    assert result["truncated"] is True and result["pending"] is True


def test_graphql_large_result_is_explicitly_incomplete(monkeypatch):
    _rest(monkeypatch, httpx.Response(200))

    @contextmanager
    def client(*a, **kw):
        response = httpx.Response(200, json={"data": {"orders": "x" * 5000}})
        @contextmanager
        def stream(*a, **kw):
            with closing(httpx.Response(200, headers=response.headers,
                                        stream=httpx.ByteStream(response.content))) as streamed:
                yield streamed
        yield SimpleNamespace(stream=stream)

    monkeypatch.setattr(_ssrf, "safe_client", client)
    tool = _rest_connector.make_graphql_tool(
        name="client_audit", base_url_env="CLIENT_AUDIT_BASE_URL", token_env="CLIENT_AUDIT_TOKEN",
        description="Synthetic GraphQL response",
    )
    result = json.loads(tool.fn({"query": "{ orders { id } }"}))
    assert result["truncated"] is True
    assert tool.fn({"query": "{ orders { id } }", "_capability_allow_hosts": ["other.test"]}).startswith("ERROR:")


def test_xlsx_replace_failure_preserves_original_and_cleans_temporary(tmp_path, monkeypatch):
    pytest.importorskip("openpyxl")
    path = tmp_path / "orders.xlsx"
    spreadsheet._xlsx_write(path, [["order", "quantity"], ["0007", 500]], None)
    original = path.read_bytes()

    def fail(*args):
        raise PermissionError("synthetic locked workbook")

    monkeypatch.setattr(spreadsheet.os, "replace", fail)
    result = spreadsheet._run({"op": "set_cell", "path": str(path), "cell": "B2", "value": 900})
    assert result.startswith("ERROR:") and path.read_bytes() == original
    assert sorted(p.name for p in tmp_path.iterdir()) == ["orders.xlsx", "orders.xlsx.lock"]


def test_pdf_local_size_limit_is_enforced_before_parser(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(pdf_reader, "_MAX_PDF_BYTES", 10)
    (tmp_path / "large.pdf").write_bytes(b"x" * 11)
    assert pdf_reader._run_read_pdf({"source": "large.pdf"}).startswith("ERROR:")


def test_shoring_measurements_cannot_be_displaced_by_other_departments():
    from .test_shoring import _Goal, _World

    now = 1000000.0
    world = _World(goals=[_Goal(i, "support", "done", now) for i in range(2001)] + [
        _Goal(3000, "finance_ap", "done", now),
    ])
    function = shoring.Function("ap", "AP", department="finance_ap")
    assert shoring.function_status(function, world, now=now)["delivered"] == 1


def test_shoring_partial_sample_never_claims_sla_is_met():
    from .test_shoring import _Goal, _World

    now = 1000000.0
    world = _World(goals=[_Goal(i, "finance_ap", "done", now) for i in range(2001)])
    function = shoring.Function("ap", "AP", department="finance_ap", slas=[
        shoring.SLATarget("Throughput", "throughput_per_day", 1),
    ])
    result = shoring.function_status(function, world, now=now)
    assert result["measurement_complete"] is False
    assert result["overall"] == "no_data" and result["slas"][0]["actual"] is None


def test_shoring_unreadable_world_and_book_do_not_look_empty():
    def unavailable(**kwargs):
        raise OSError("synthetic database failure")

    with pytest.raises(RuntimeError, match="unavailable"):
        shoring.sla_status(shoring.Function("ap", "AP"), SimpleNamespace(list_goals=unavailable))
    path = shoring._book_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("corrupt", encoding="utf-8")
    with pytest.raises(RuntimeError):
        shoring.book_status(SimpleNamespace())


@pytest.mark.parametrize("actual,expected", [(0, "met"), (1, "breached")])
def test_shoring_zero_exception_target_is_measurable(actual, expected):
    assert shoring._band("max_exception_rate_pct", 0, actual) == expected


def test_kubernetes_copy_uses_unambiguous_local_operands(tmp_path, monkeypatch):
    from maverick.sandbox.kubernetes import KubernetesBackend

    calls = []

    def run(args, **kwargs):
        calls.append((args, kwargs))
        if "tar" in args:
            import tarfile
            with tarfile.open(fileobj=kwargs["stdout"], mode="w"):
                pass
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", run)
    from .test_kubernetes_workspace_transfer import _capture_using_fake_run
    monkeypatch.setattr("maverick.sandbox.workspace_transfer.capture_archive", _capture_using_fake_run)
    backend = KubernetesBackend(workdir=tmp_path / "workspace", allow_network=True)
    (backend.workdir / "input.txt").write_text("input")
    assert backend._copy_in("fixture") is None
    from maverick.sandbox import workspace_transfer
    recovery = workspace_transfer.recovery_directory()
    assert backend._copy_out("fixture", {}, recovery) == ""
    transfers = [(args, kw) for args, kw in calls if "cp" in args]
    assert len(transfers) == 1  # export uses a binary stream, not a colon-bearing local operand
    for args, kwargs in transfers:
        assert kwargs["cwd"] == backend.workdir
        operands = args[args.index("cp") + 1:]
        assert sum(":" in operand for operand in operands) == 1


def test_kubernetes_additive_allow_policy_refuses_execution(tmp_path, monkeypatch):
    from maverick.sandbox.kubernetes import KubernetesBackend

    from .test_sandbox_kubernetes_networkpolicy import _fake_kubectl, _policy

    calls = _fake_kubectl(monkeypatch, policies=[_policy(), _policy(egress=[{}])])
    assert KubernetesBackend(workdir=tmp_path).exec("true").exit_code == 2
    assert not any("run" in args for args in calls)


def test_kubernetes_changed_policy_is_rechecked(tmp_path, monkeypatch):
    from maverick.sandbox.kubernetes import KubernetesBackend

    from .test_sandbox_kubernetes_networkpolicy import _fake_kubectl, _policy

    policies = [_policy()]
    _fake_kubectl(monkeypatch, policies=policies)
    backend = KubernetesBackend(workdir=tmp_path / "workspace")
    assert backend.exec("true").exit_code == 0
    policies.clear()
    assert backend.exec("true").exit_code == 2


def test_response_non_ascii_headers_cannot_exhaust_the_envelope():
    response = httpx.Response(200, headers=[
        (name, b"\xff" * 512) for name in (b"etag", b"last-modified", b"retry-after")
    ])
    rendered = _rest_connector._rest_response(response, {"id": 7}, {"response_format": "metadata"}, "")
    assert len(rendered) <= 4000
    result = json.loads(rendered)
    assert result["body"] == {"id": 7}
    assert result["omitted_headers"] == ["etag", "last-modified", "retry-after"]


def test_pdf_table_preserves_zero_false_and_cell_boundaries():
    result = pdf_reader._table_to_markdown([["Value"], [0], [False], ["a|b\nc"]])
    assert "| 0 |" in result and "| False |" in result
    assert r"a\|b<br>c" in result


def test_pdf_blank_selected_page_requests_ocr(tmp_path, monkeypatch):
    pypdf = pytest.importorskip("pypdf")
    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=72, height=72)
    with (tmp_path / "blank.pdf").open("wb") as stream:
        writer.write(stream)
    monkeypatch.setenv("MAVERICK_ISOLATE_PARSERS", "1")
    result = pdf_reader.read_pdf(SimpleNamespace(workdir=tmp_path)).fn({"source": "blank.pdf"})
    assert result.startswith("ERROR:") and "OCR" in result


def test_pdf_requested_tables_are_not_silently_downgraded_to_plain_text(monkeypatch):
    monkeypatch.setattr(pdf_reader, "_extract_with_pdfplumber", lambda *a: None)
    monkeypatch.setattr(pdf_reader, "_extract_with_pypdf", lambda *a: pytest.fail("table request must not silently lose structure"))
    result = pdf_reader.extract_text_from_bytes(b"synthetic", include_tables=True)
    assert result.startswith("ERROR:") and "pdfplumber" in result


@pytest.mark.parametrize("damage", ["sla_metric", "sla_count", "status", "timestamp"])
def test_shoring_nested_record_damage_refuses_edits_without_data_loss(damage):
    shoring.upsert(shoring.Function(key="ap", name="Accounts Payable"))
    path = shoring._book_path()
    rows = json.loads(path.read_text(encoding="utf-8"))
    if damage == "sla_metric":
        rows[0]["slas"] = [{"name": "Cycle", "metric": "unknown", "target": 1}]
    elif damage == "sla_count":
        rows[0]["slas"] = [{"name": "Cycle", "metric": "throughput_per_day", "target": 1}] * 13
    elif damage == "status":
        rows[0]["status"] = "corrupted"
    else:
        rows[0]["updated_at"] = "corrupted"
    original = json.dumps(rows)
    path.write_text(original, encoding="utf-8")
    with pytest.raises(RuntimeError, match="invalid function"):
        shoring.upsert(shoring.Function(key="support", name="Support"))
    assert path.read_text(encoding="utf-8") == original


@pytest.mark.parametrize("filename,op", [("orders.csv", "write"), ("orders.xlsx", "write"), ("orders.xlsx", "set_cell")])
def test_spreadsheet_mutations_wait_for_shared_file_lock(tmp_path, filename, op):
    if filename.endswith("xlsx"):
        pytest.importorskip("openpyxl")
    tool = spreadsheet.spreadsheet(SimpleNamespace(workdir=tmp_path))
    assert tool.fn({"op": "write", "path": filename, "rows": [["original"]]}).startswith("wrote")
    path = tmp_path / filename
    original = path.read_bytes()
    started = threading.Event()

    def mutate():
        started.set()
        return tool.fn({"op": op, "path": filename, "rows": [["updated"]], "cell": "A1", "value": "updated"})

    with ThreadPoolExecutor(max_workers=1) as pool:
        with cross_process_lock(path, strict=True):
            future = pool.submit(mutate)
            assert started.wait(2)
            with pytest.raises(FutureTimeoutError):
                future.result(timeout=0.2)
            assert path.read_bytes() == original
        assert not future.result(timeout=5).startswith("ERROR:")
    assert json.loads(tool.fn({"op": "read", "path": filename})) == [["updated"]]
