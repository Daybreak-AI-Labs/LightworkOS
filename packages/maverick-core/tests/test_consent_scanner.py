from __future__ import annotations

import hashlib
import json
import struct
import sys
import threading
import types
from dataclasses import asdict

import maverick.consent_scanner as scanner_module
import pytest
from maverick import config
from maverick.consent_scanner import (
    ConsentScanner,
    ConsentScannerConfigError,
    ConsentScannerValidationError,
    CookieMetadata,
    NetworkMetadata,
    PageCapture,
    PlaywrightPageCollector,
    ScanLimits,
    enabled,
    require_enabled,
)

NOW = 1_800_000_000.0


class Clock:
    def __init__(self) -> None:
        self.value = NOW

    def __call__(self) -> float:
        self.value += 1
        return self.value


class FakeCollector:
    def __init__(self, captures: dict[str, PageCapture | Exception]) -> None:
        self.captures = captures
        self.calls: list[tuple[str, frozenset[str], str | None]] = []

    def capture(
        self,
        url: str,
        *,
        navigation_hosts: frozenset[str],
        limits: ScanLimits,
        auth_secret_ref: str | None,
    ) -> PageCapture:
        del limits
        self.calls.append((url, navigation_hosts, auth_secret_ref))
        result = self.captures[url]
        if isinstance(result, Exception):
            raise result
        return result


class ScriptedSocket:
    def __init__(self, incoming: bytes = b"") -> None:
        self.incoming = bytearray(incoming)
        self.sent = bytearray()
        self.timeout: float | None = None
        self.closed = False

    def recv(self, count: int) -> bytes:
        if not self.incoming:
            return b""
        chunk = bytes(self.incoming[:count])
        del self.incoming[:count]
        return chunk

    def sendall(self, value: bytes) -> None:
        self.sent.extend(value)

    def settimeout(self, value: float) -> None:
        self.timeout = value

    def shutdown(self, _how: int) -> None:
        return None

    def close(self) -> None:
        self.closed = True


def _socks_domain_request(host: str, port: int, *, command: int = 1) -> bytes:
    encoded = host.encode("ascii")
    return (
        b"\x05\x01\x00"
        + bytes((5, command, 0, 3, len(encoded)))
        + encoded
        + struct.pack("!H", port)
    )


@pytest.fixture(autouse=True)
def scanner_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "config_source_errors", list)
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "consent_preferences": {
                "enable": True,
                "scanner": {"enable": True},
            }
        },
    )


def _capture(
    url: str,
    *,
    links: tuple[str, ...] = (),
    network: tuple[NetworkMetadata, ...] = (),
    cookies: tuple[CookieMetadata, ...] = (),
    storage_keys: tuple[str, ...] = (),
    network_truncated: bool = False,
) -> PageCapture:
    return PageCapture(
        final_url=url,
        links=links,
        network=network,
        cookies=cookies,
        storage_keys=storage_keys,
        network_truncated=network_truncated,
    )


def _scanner(collector: FakeCollector, *, public: bool = True) -> ConsentScanner:
    return ConsentScanner(
        collector,
        clock=Clock(),
        id_factory=lambda: "0123456789abcdef",
        host_is_public=lambda _host: public,
    )


def test_enabled_requires_both_closed_config_gates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert enabled() is True

    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {"consent_preferences": {"enable": True}},
    )
    assert enabled() is False
    with pytest.raises(ConsentScannerConfigError):
        require_enabled()

    monkeypatch.setattr(config, "config_source_errors", lambda: ["invalid"])
    assert enabled() is False


def test_scan_discovers_bounded_metadata_without_retaining_values_or_urls() -> None:
    root = "https://shop.example.test/"
    second = "https://shop.example.test/account?view=privacy"
    collector = FakeCollector(
        {
            root: _capture(
                root,
                links=(second, "https://outside.example.test/tracker"),
                network=(
                    NetworkMetadata(
                        "https://metrics.vendor.test/collect?user=private-value",
                        "fetch",
                    ),
                ),
                cookies=(
                    CookieMetadata(
                        "shop.example.test",
                        "session-cookie-secret",
                        True,
                        True,
                        "Lax",
                    ),
                ),
                storage_keys=("customer-storage-secret",),
            ),
            second: _capture(
                second,
                network=(
                    NetworkMetadata(
                        "https://metrics.vendor.test/collect?another=secret",
                        "fetch",
                    ),
                ),
            ),
        }
    )

    report = _scanner(collector).scan(
        "tenant-a",
        "property-shop",
        [root],
        ["https://shop.example.test"],
    )

    assert report.complete is True
    assert report.truncated is False
    assert report.pages_attempted == report.pages_captured == 2
    assert len(report.page_sha256) == 2
    assert len(report.findings) == 3
    assert {finding.kind for finding in report.findings} == {
        "network",
        "cookie",
        "storage",
    }
    assert all(finding.classification == "unknown" for finding in report.findings)
    assert all(len(finding.evidence_sha256) == 64 for finding in report.findings)
    assert collector.calls == [
        (root, frozenset({"shop.example.test"}), None),
        (second, frozenset({"shop.example.test"}), None),
    ]

    serialized = json.dumps(asdict(report), sort_keys=True)
    for prohibited in (
        "tenant-a",
        root,
        second,
        "private-value",
        "session-cookie-secret",
        "customer-storage-secret",
    ):
        assert prohibited not in serialized
    assert report.property_id == "property-shop"
    digest_body = asdict(report)
    expected_digest = digest_body.pop("report_sha256")
    assert hashlib.sha256(
        json.dumps(
            digest_body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    ).hexdigest() == expected_digest


def test_capture_failure_and_collector_truncation_never_claim_completeness() -> None:
    root = "https://shop.example.test/"
    failing = "https://shop.example.test/failing"
    collector = FakeCollector(
        {
            root: _capture(root, links=(failing,), network_truncated=True),
            failing: RuntimeError("credential and page content must not escape"),
        }
    )

    report = _scanner(collector).scan(
        "tenant-a",
        "property-shop",
        [root],
        ["https://shop.example.test"],
    )

    assert report.complete is False
    assert report.truncated is True
    assert report.pages_attempted == 2
    assert report.pages_captured == 1
    assert report.errors == (
        {
            "page_sha256": report.errors[0]["page_sha256"],
            "error_code": "RuntimeError",
        },
    )
    assert "credential" not in json.dumps(asdict(report))


def test_max_pages_marks_a_report_incomplete_when_work_remains() -> None:
    root = "https://shop.example.test/"
    next_url = "https://shop.example.test/next"
    collector = FakeCollector(
        {
            root: _capture(root, links=(next_url,)),
            next_url: _capture(next_url),
        }
    )

    report = _scanner(collector).scan(
        "tenant-a",
        "property-shop",
        [root],
        ["https://shop.example.test"],
        limits=ScanLimits(max_pages=1),
    )

    assert report.pages_attempted == 1
    assert report.pages_captured == 1
    assert report.truncated is True
    assert report.complete is False


def test_authenticated_scan_requires_both_secret_reference_and_owner_consent() -> None:
    root = "https://shop.example.test/"
    collector = FakeCollector({root: _capture(root)})
    scanner = _scanner(collector)

    with pytest.raises(ConsentScannerValidationError, match="explicit"):
        scanner.scan(
            "tenant-a",
            "property-shop",
            [root],
            ["https://shop.example.test"],
            auth_secret_ref="env:SCAN_STATE",
        )
    with pytest.raises(ConsentScannerValidationError, match="without a secret"):
        scanner.scan(
            "tenant-a",
            "property-shop",
            [root],
            ["https://shop.example.test"],
            authenticated_scan_consent=True,
        )

    scanner.scan(
        "tenant-a",
        "property-shop",
        [root],
        ["https://shop.example.test"],
        auth_secret_ref="env:SCAN_STATE",
        authenticated_scan_consent=True,
    )
    assert collector.calls[-1][2] == "env:SCAN_STATE"


def test_scan_rejects_unenrolled_private_and_malformed_origins() -> None:
    root = "https://shop.example.test/"
    collector = FakeCollector({root: _capture(root)})

    with pytest.raises(ConsentScannerValidationError, match="outside enrolled"):
        _scanner(collector).scan(
            "tenant-a",
            "property-shop",
            ["https://other.example.test/"],
            ["https://shop.example.test"],
        )
    with pytest.raises(ConsentScannerValidationError, match="public"):
        _scanner(collector, public=False).scan(
            "tenant-a",
            "property-shop",
            [root],
            ["https://shop.example.test"],
        )
    with pytest.raises(ConsentScannerValidationError, match="exact HTTPS"):
        _scanner(collector).scan(
            "tenant-a",
            "property-shop",
            [root],
            ["https://shop.example.test/path"],
        )


def test_playwright_request_admission_is_navigation_and_ssrf_bounded() -> None:
    collector = PlaywrightPageCollector(
        host_is_public=lambda host: host not in {"private.example.test", "localhost"}
    )
    hosts = frozenset({"shop.example.test"})

    assert collector._admit_request(  # noqa: SLF001
        "https://shop.example.test/account", navigation=True, hosts=hosts
    )
    assert collector._admit_request(  # noqa: SLF001
        "https://cdn.vendor.test/code.js", navigation=False, hosts=hosts
    )
    assert collector._admit_request(  # noqa: SLF001
        "wss://events.vendor.test/socket", navigation=False, hosts=hosts
    )
    assert collector._admit_request(  # noqa: SLF001
        "ws://events.vendor.test/socket", navigation=False, hosts=hosts
    )
    assert not collector._admit_request(  # noqa: SLF001
        "wss://events.vendor.test:80/socket", navigation=False, hosts=hosts
    )
    assert not collector._admit_request(  # noqa: SLF001
        "https://cdn.vendor.test/landing", navigation=True, hosts=hosts
    )
    assert not collector._admit_request(  # noqa: SLF001
        "https://private.example.test/", navigation=False, hosts=hosts
    )
    assert not collector._admit_request(  # noqa: SLF001
        "https://user:pass@shop.example.test/", navigation=True, hosts=hosts
    )
    assert not collector._admit_request(  # noqa: SLF001
        "file:///etc/passwd", navigation=False, hosts=hosts
    )


def test_pinned_proxy_resolves_once_and_connects_to_the_admitted_public_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolver_calls: list[tuple[str, int]] = []
    connector_calls: list[tuple[str, int, float]] = []
    client = ScriptedSocket(_socks_domain_request("cdn.vendor.test", 443))
    upstream = ScriptedSocket()

    def resolver(host: str, port: int) -> tuple[str, ...]:
        resolver_calls.append((host, port))
        return ("93.184.216.34",)

    def connector(ip: str, port: int, timeout: float) -> ScriptedSocket:
        connector_calls.append((ip, port, timeout))
        return upstream

    monkeypatch.setattr(
        scanner_module.select,
        "select",
        lambda *_args, **_kwargs: ([client], [], []),
    )
    proxy = scanner_module._PinnedSocksProxy(  # noqa: SLF001
        resolver=resolver,
        connector=connector,
    )

    proxy._handle_client(client)  # noqa: SLF001

    assert resolver_calls == [("cdn.vendor.test", 443)]
    assert connector_calls == [("93.184.216.34", 443, 15.0)]
    assert bytes(client.sent) == (
        b"\x05\x00\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    )
    assert upstream.closed is True


def test_pinned_connector_opens_the_exact_literal_without_name_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened: list[tuple[int, int]] = []
    connected: list[tuple[str, int]] = []

    class DirectSocket(ScriptedSocket):
        def connect(self, target: tuple[str, int]) -> None:
            connected.append(target)

    direct = DirectSocket()

    def socket_factory(family: int, kind: int) -> DirectSocket:
        opened.append((family, kind))
        return direct

    monkeypatch.setattr(scanner_module.socket, "socket", socket_factory)

    result = scanner_module._connect_literal_ip(  # noqa: SLF001
        "93.184.216.34",
        443,
        4.0,
    )

    assert result is direct
    assert opened == [(scanner_module.socket.AF_INET, scanner_module.socket.SOCK_STREAM)]
    assert connected == [("93.184.216.34", 443)]
    assert direct.timeout == 4.0


@pytest.mark.parametrize(
    ("host", "answers"),
    [
        ("127.0.0.1", ()),
        ("10.0.0.8", ()),
        ("metadata.vendor.test", ("169.254.169.254",)),
        ("mixed.vendor.test", ("93.184.216.34", "127.0.0.1")),
    ],
)
def test_pinned_proxy_rejects_private_loopback_and_mixed_dns_answers(
    host: str,
    answers: tuple[str, ...],
) -> None:
    def resolver(_host: str, _port: int) -> tuple[str, ...]:
        return answers

    proxy = scanner_module._PinnedSocksProxy(resolver=resolver)  # noqa: SLF001

    with pytest.raises(scanner_module._SocksRequestRejected):  # noqa: SLF001
        proxy._pin_target(host, 443)  # noqa: SLF001


def test_pinned_proxy_closes_precheck_to_connect_dns_rebinding_window() -> None:
    collector = PlaywrightPageCollector(host_is_public=lambda _host: True)
    assert collector._admit_request(  # noqa: SLF001
        "https://rebind.vendor.test/asset.js",
        navigation=False,
        hosts=frozenset({"shop.example.test"}),
    )

    proxy = scanner_module._PinnedSocksProxy(  # noqa: SLF001
        resolver=lambda _host, _port: ("127.0.0.1",)
    )
    with pytest.raises(scanner_module._SocksRequestRejected):  # noqa: SLF001
        proxy._pin_target("rebind.vendor.test", 443)  # noqa: SLF001


def test_pinned_proxy_dns_wait_is_bounded() -> None:
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()

    def blocked_resolver(_host: str, _port: int) -> tuple[str, ...]:
        entered.set()
        try:
            release.wait(timeout=2.0)
            return ("93.184.216.34",)
        finally:
            finished.set()

    proxy = scanner_module._PinnedSocksProxy(  # noqa: SLF001
        resolver=blocked_resolver,
        dns_timeout_seconds=0.01,
    )
    try:
        with pytest.raises(scanner_module._SocksRequestRejected):  # noqa: SLF001
            proxy._pin_target("slow.vendor.test", 443)  # noqa: SLF001
        assert entered.is_set()
    finally:
        release.set()
        assert finished.wait(timeout=1.0)


@pytest.mark.parametrize(
    ("packet", "reply_code"),
    [
        (_socks_domain_request("cdn.vendor.test", 443, command=2), 7),
        (_socks_domain_request("cdn.vendor.test", 22), 2),
    ],
)
def test_pinned_proxy_rejects_unsupported_command_and_port(
    packet: bytes,
    reply_code: int,
) -> None:
    client = ScriptedSocket(packet)

    with pytest.raises(scanner_module._SocksRequestRejected):  # noqa: SLF001
        scanner_module._PinnedSocksProxy._read_request(client)  # noqa: SLF001

    assert bytes(client.sent[:2]) == b"\x05\x00"
    assert client.sent[3] == reply_code


def test_playwright_capture_launches_chromium_through_the_pinned_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launched: dict[str, object] = {}
    target = "https://shop.example.test/"

    class FakePinnedProxy:
        server_url = "socks5://127.0.0.1:49152"

        def __init__(self, **_kwargs: object) -> None:
            pass

        def __enter__(self) -> FakePinnedProxy:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    class FakePage:
        url = target

        def goto(self, url: str, **_kwargs: object) -> None:
            self.url = url

        def wait_for_timeout(self, _milliseconds: int) -> None:
            return None

        def eval_on_selector_all(self, *_args: object) -> list[object]:
            return []

        def evaluate(self, *_args: object) -> list[object]:
            return []

    class FakeContext:
        def new_page(self) -> FakePage:
            return FakePage()

        def route(self, *_args: object) -> None:
            return None

        def cookies(self) -> list[object]:
            return []

        def close(self) -> None:
            return None

    class FakeBrowser:
        def new_context(self, **_kwargs: object) -> FakeContext:
            return FakeContext()

        def close(self) -> None:
            return None

    class FakeChromium:
        def launch(self, **kwargs: object) -> FakeBrowser:
            launched.update(kwargs)
            return FakeBrowser()

    class FakePlaywright:
        chromium = FakeChromium()

    class FakePlaywrightContext:
        def __enter__(self) -> FakePlaywright:
            return FakePlaywright()

        def __exit__(self, *_args: object) -> None:
            return None

    playwright_package = types.ModuleType("playwright")
    playwright_package.__path__ = []  # type: ignore[attr-defined]
    playwright_sync = types.ModuleType("playwright.sync_api")
    playwright_sync.sync_playwright = FakePlaywrightContext  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "playwright", playwright_package)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", playwright_sync)
    monkeypatch.setattr(scanner_module, "_PinnedSocksProxy", FakePinnedProxy)

    capture = PlaywrightPageCollector(host_is_public=lambda _host: True).capture(
        target,
        navigation_hosts=frozenset({"shop.example.test"}),
        limits=ScanLimits(settle_milliseconds=0),
        auth_secret_ref=None,
    )

    assert capture.final_url == target
    assert launched["headless"] is True
    assert launched["proxy"] == {
        "server": "socks5://127.0.0.1:49152",
        "bypass": "<-loopback>",
    }
    args = launched["args"]
    assert isinstance(args, list)
    assert "--disable-quic" in args
    assert "--disable-http2" in args
    assert "--proxy-bypass-list=<-loopback>" in args
    assert "--force-webrtc-ip-handling-policy=disable_non_proxied_udp" in args


@pytest.mark.parametrize(
    "limits",
    [
        ScanLimits(max_pages=0),
        ScanLimits(max_depth=21),
        ScanLimits(page_timeout_seconds=0),
        ScanLimits(max_network_events=0),
        ScanLimits(settle_milliseconds=30_001),
    ],
)
def test_scan_limits_are_finite_and_bounded(limits: ScanLimits) -> None:
    with pytest.raises(ConsentScannerValidationError):
        limits.validated()


@pytest.mark.parametrize("raises", [False, True])
def test_pinned_proxy_denies_host_policy_before_dns_or_connect(raises: bool) -> None:
    client = ScriptedSocket(_socks_domain_request("denied.vendor.test", 443))
    calls = []

    def authorize(host: str, port: int) -> bool:
        calls.append(("authorize", host, port))
        if raises:
            raise RuntimeError("policy unavailable")
        return False

    def resolver(host: str, port: int) -> tuple[str, ...]:
        calls.append(("resolve", host, port))
        return ("93.184.216.34",)

    proxy = scanner_module._PinnedSocksProxy(  # noqa: SLF001
        resolver=resolver, authorize_host=authorize,
    )
    proxy._handle_client(client)  # noqa: SLF001
    assert calls == [("authorize", "denied.vendor.test", 443)]
    assert client.sent[3] == 2
