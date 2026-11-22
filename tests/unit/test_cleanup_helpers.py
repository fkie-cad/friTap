"""Direct tests for helpers extracted during the cleanup."""

from types import SimpleNamespace

import pytest

from friTap.flow.tap_format import _BlobTable
from friTap.output import factory
from friTap.parsers.http2 import Http2Parser, _CONNECTION_PREFACE


class TestBlobTable:
    def test_offsets_follow_registration_order(self):
        t = _BlobTable()
        assert t.register(b"abc") == (0, 3)
        assert t.register(b"de") == (3, 2)
        assert t.joined() == b"abcde"

    def test_identical_blobs_deduplicated(self):
        t = _BlobTable()
        first = t.register(b"abc")
        t.register(b"zz")
        assert t.register(b"abc") == first
        assert t.joined() == b"abczz"

    def test_empty_and_bytearray(self):
        t = _BlobTable()
        t.register(b"ab")
        assert t.register(b"") == (2, 0)
        assert t.register(bytearray(b"ab")) == (0, 2)
        assert t.joined() == b"ab"


class _Fmt:
    def __init__(self, protocol, tables=False):
        self.protocol = protocol
        self.writes_decryption_tables = tables


def _config(keylog, scan=None):
    return SimpleNamespace(
        protocols=["x"], protocol="x",
        hooking=SimpleNamespace(scan_keys_region=scan),
        output=SimpleNamespace(keylog=keylog))


@pytest.fixture
def stub_formatters(monkeypatch):
    def _set(formatters):
        monkeypatch.setattr(factory, "_active_keylog_formatters",
                            lambda protocols, registry: list(formatters))
        monkeypatch.setattr("friTap.config.memory_scan_only", lambda c: False)
    return _set


class TestResolveKeylogFormatters:
    def test_uat_formatters_split_out(self, stub_formatters):
        tls, ipsec = _Fmt("tls"), _Fmt("ipsec", tables=True)
        stub_formatters([tls, ipsec])
        active, uat = factory._resolve_keylog_formatters(_config("k.log"), None, object())
        assert active == [tls]
        assert uat == [ipsec]

    def test_scan_region_adds_scan_candidate_once(self, stub_formatters):
        stub_formatters([_Fmt("tls")])
        active, _ = factory._resolve_keylog_formatters(_config("k.log", "rw-"), None, object())
        assert [getattr(f, "protocol", None) for f in active] == ["tls", "scan_candidate"]

    def test_protocol_handler_fallback_without_registry(self, monkeypatch):
        monkeypatch.setattr(factory, "_active_keylog_formatters", lambda p, r: [])
        fmt = _Fmt("ssh")
        handler = SimpleNamespace(keylog_formatter=lambda: fmt)
        active, uat = factory._resolve_keylog_formatters(_config("k.log"), handler, None)
        assert active == [fmt] and uat == []


class TestAddKeylogHandlers:
    def _run(self, config):
        handlers, live = [], {}
        logger = SimpleNamespace(warning=lambda *a, **k: None, info=lambda *a, **k: None)
        split = factory._add_keylog_handlers(config, None, object(), logger, handlers, live)
        return split, handlers, live

    def test_no_keylog_returns_none(self, stub_formatters):
        stub_formatters([_Fmt("tls")])
        split, handlers, _ = self._run(_config(None))
        assert split is None and handlers == []

    def test_single_formatter_uses_plain_path(self, stub_formatters, tmp_path):
        stub_formatters([_Fmt("tls")])
        path = str(tmp_path / "k.log")
        split, handlers, live = self._run(_config(path))
        assert split is None and len(handlers) == 1
        assert handlers[0]._path == path
        assert "keylogs" not in live

    def test_multiple_formatters_split_paths(self, stub_formatters, tmp_path):
        stub_formatters([_Fmt("tls"), _Fmt("ssh")])
        path = str(tmp_path / "k.log")
        split, handlers, live = self._run(_config(path))
        assert split == {"tls": str(tmp_path / "k.tls.log"),
                         "ssh": str(tmp_path / "k.ssh.log")}
        assert live["keylogs"] == split
        assert len(handlers) == 2

    def test_uat_only_adds_ipsec_handler(self, stub_formatters, tmp_path):
        from friTap.output.ipsec_decryption_tables import IPsecDecryptionTableHandler
        stub_formatters([_Fmt("ipsec", tables=True)])
        split, handlers, _ = self._run(_config(str(tmp_path / "k.log")))
        assert split is None
        assert [type(h) for h in handlers] == [IPsecDecryptionTableHandler]


class TestStripPreface:
    def _parser(self):
        p = Http2Parser()
        p._preface_seen["c"] = False
        return p

    def test_preface_present_is_stripped(self):
        p = self._parser()
        buf = bytearray(_CONNECTION_PREFACE + b"rest")
        assert p._strip_preface("c", buf) is True
        assert bytes(buf) == b"rest"
        assert p._preface_seen["c"] is True

    def test_no_preface_left_untouched(self):
        p = self._parser()
        buf = bytearray(b"\x00\x00\x00\x04\x00\x00\x00\x00\x00")
        assert p._strip_preface("c", buf) is True
        assert len(buf) == 9
        assert p._preface_seen["c"] is False

    def test_partial_preface_waits(self):
        p = self._parser()
        buf = bytearray(_CONNECTION_PREFACE[:10])
        assert p._strip_preface("c", buf) is False
        assert bytes(buf) == _CONNECTION_PREFACE[:10]

    def test_already_seen_short_circuits(self):
        p = self._parser()
        p._preface_seen["c"] = True
        buf = bytearray(_CONNECTION_PREFACE)
        assert p._strip_preface("c", buf) is True
        assert bytes(buf) == _CONNECTION_PREFACE
