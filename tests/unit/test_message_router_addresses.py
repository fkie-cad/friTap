"""Agent socket fields are untyped and untrusted.

Malformed families, addresses and ports must never reach a BPF / Wireshark
display filter string (``PCAP.get_filter_from_traced_sockets``) or the
DatalogEvent address fields as raw agent text.
"""

import logging
import types

import pytest

from friTap.events import DatalogEvent
from friTap.legacy import ssl_logger_core
from friTap.legacy.ssl_logger_core import (
    SSL_Logger,
    coerce_port,
    get_addr_string,
    resolve_ss_family,
)
from friTap.message_router import MessageRouter
from friTap.pcap import PCAP

EVIL = "1.2.3.4 or port 22"
V6_HEX = "20010db8000000000000000000000001"


class _Bus:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


@pytest.fixture(autouse=True)
def _rearm_warn_once(monkeypatch):
    monkeypatch.setattr(ssl_logger_core, "_invalid_socket_field_warned", False)


class TestGetAddrString:
    def test_valid_ipv4_int_and_string(self):
        assert get_addr_string(0x7F000001, "AF_INET") == "127.0.0.1"
        assert get_addr_string("10.0.0.1", "AF_INET") == "10.0.0.1"

    def test_valid_ipv6_hex_and_text(self):
        assert get_addr_string(V6_HEX, "AF_INET6") == "2001:db8::1"
        assert get_addr_string("2001:db8::1", "AF_INET6") == "2001:db8::1"

    @pytest.mark.parametrize("addr, family", [
        (EVIL, "AF_INET"),
        (2 ** 40, "AF_INET"),
        (-1, "AF_INET"),
        (True, "AF_INET"),
        ("zz" * 16, "AF_INET6"),
        ("not an ip", "AF_INET6"),
        (0x7F000001, "AF_INET6"),
        (EVIL, "AF_EVIL or host 6.6.6.6"),
        (0x7F000001, None),
        ("/tmp/sock", "AF_UNIX"),
        ({"x": 1}, "AF_INET"),
    ])
    def test_invalid_never_returns_agent_text(self, addr, family):
        assert get_addr_string(addr, family) == ""

    def test_missing_address_stays_missing(self):
        assert get_addr_string("", "AF_INET") == ""
        assert get_addr_string(None, "AF_INET6") == ""

    def test_warns_once(self, caplog):
        with caplog.at_level(logging.WARNING):
            get_addr_string(EVIL, "AF_INET")
            get_addr_string(EVIL, "AF_INET")
        assert caplog.text.count("malformed") == 1


class TestPortsAndFamilies:
    @pytest.mark.parametrize("port, expected", [
        (443, 443), (0, 0), (65535, 65535), (65536, 0), (-1, 0),
        ("443", 0), (True, 0), (float("inf"), 0), (None, 0), (2 ** 70, 0),
    ])
    def test_coerce_port(self, port, expected):
        assert coerce_port(port) == expected

    @pytest.mark.parametrize("raw, expected", [
        ("AF_INET", ("AF_INET", "AF_INET")),
        ("AF_INET6", ("AF_INET6", "AF_INET6")),
        ("AF_UNIX", ("AF_UNIX", "AF_UNIX")),
        (None, ("AF_INET", "AF_INET")),
        ("AF_PACKET", ("AF_INET", None)),
        (2, ("AF_INET", None)),
    ])
    def test_resolve_ss_family(self, raw, expected):
        assert resolve_ss_family(raw) == expected


class TestRouterResolveAddresses:
    def test_valid_payload_unchanged(self):
        out = MessageRouter._resolve_addresses({
            "ss_family": "AF_INET", "src_addr": 0x0A000001, "src_port": 5555,
            "dst_addr": 0x08080808, "dst_port": 443})
        assert out == ("10.0.0.1", 5555, "8.8.8.8", 443, "AF_INET",
                       0x0A000001, 0x08080808)

    def test_hostile_payload_is_neutralised(self):
        out = MessageRouter._resolve_addresses({
            "ss_family": "AF_EVIL) or (host 6.6.6.6", "src_addr": EVIL,
            "src_port": 99999, "dst_addr": 0x08080808, "dst_port": "443; rm"})
        assert out == ("", 0, "", 0, "AF_INET", "", "")

    def test_datalog_event_carries_only_validated_fields(self):
        bus = _Bus()
        router = MessageRouter(bus)
        router._emit_datalog({
            "ss_family": "AF_INET", "src_addr": EVIL, "src_port": -5,
            "dst_addr": 2 ** 33, "dst_port": 70000, "function": "SSL_read"}, b"data")
        (event,) = [e for e in bus.events if isinstance(e, DatalogEvent)]
        assert (event.src_addr, event.src_port, event.dst_addr, event.dst_port) == ("", 0, "", 0)
        assert event.src_addr_raw == "" and event.dst_addr_raw == ""


def _tracking_logger():
    obj = SSL_Logger.__new__(SSL_Logger)
    obj._config = types.SimpleNamespace(
        output=types.SimpleNamespace(socket_trace=True, full_capture=True))
    obj._event_bus = _Bus()
    obj.traced_Socket_Set = set()
    obj.traced_scapy_socket_Set = set()
    return obj


class TestFilterStrings:
    HOSTILE_PAYLOADS = [
        {"ss_family": "AF_EVIL or host 6.6.6.6", "src_addr": EVIL, "dst_addr": EVIL,
         "src_port": 1, "dst_port": 2},
        {"ss_family": "AF_INET", "src_addr": EVIL, "dst_addr": 0x08080808,
         "src_port": 1, "dst_port": 2},
        {"ss_family": "AF_INET6", "src_addr": "::1 or host 6.6.6.6", "dst_addr": V6_HEX,
         "src_port": 1, "dst_port": 2},
        {"ss_family": "AF_UNIX", "src_addr": "/tmp/s", "dst_addr": "/tmp/t",
         "src_port": 0, "dst_port": 0},
        {"ss_family": "AF_INET", "src_addr": 2 ** 40, "dst_addr": 1,
         "src_port": 1, "dst_port": 2},
    ]

    @pytest.mark.parametrize("payload", HOSTILE_PAYLOADS)
    def test_hostile_socket_never_reaches_filters(self, payload):
        obj = _tracking_logger()
        obj._track_traced_socket(payload)
        for sockets in (obj.traced_Socket_Set, obj.traced_scapy_socket_Set):
            assert PCAP.get_filter_from_traced_sockets(sockets, "bpf") == ""
            assert PCAP.get_filter_from_traced_sockets(sockets, "display") == ""
        assert obj._event_bus.events == []

    def test_out_of_range_ports_are_coerced(self):
        obj = _tracking_logger()
        obj._track_traced_socket({"ss_family": "AF_INET", "src_addr": 0x0A000001,
                                  "dst_addr": 0x08080808, "src_port": 70000,
                                  "dst_port": "443 or 1=1"})
        (entry,) = obj.traced_Socket_Set
        entry = dict(entry)
        assert entry["src_port"] == 0 and entry["dst_port"] == 0

    def test_valid_socket_still_produces_filter(self):
        obj = _tracking_logger()
        obj._track_traced_socket({"ss_family": "AF_INET", "src_addr": 0x0A000001,
                                  "dst_addr": 0x08080808, "src_port": 5555,
                                  "dst_port": 443})
        bpf = PCAP.get_filter_from_traced_sockets(obj.traced_scapy_socket_Set, "bpf")
        assert bpf == "(src host 10.0.0.1 and dst host 8.8.8.8)"
        assert len(obj._event_bus.events) == 1
