"""Defensive-guard tests for ``PCAP._emit_pcapng_with_dsb``.

Plaintext-mode never reaches this code path (gated by ``if full_capture:``),
so these tests cover the *full-capture* case where the temp source pcap
might be missing or empty (e.g. the sniff thread never received a
single packet). The guard must produce a usable pcapng with the TLS
keys preserved instead of raising.
"""

import logging
import os
import struct
import types

import pytest

from friTap.pcap import PCAP


def _make_stub_emitter(pcap_file_name: str):
    """Build a minimal stub object that the unbound _emit_pcapng_with_dsb
    method can be invoked against. Avoids the cost of building a real
    PCAP instance (which spawns threads on FullCapture mode).
    """
    stub = types.SimpleNamespace()
    stub.pcap_file_name = pcap_file_name
    # Use a logger OUTSIDE the friTap hierarchy so caplog can observe it
    # regardless of whether setup_fritap_logging has been called by an
    # earlier test (which sets friTap.propagate = False).
    stub.logger = logging.getLogger("test_dsb_guard")
    stub._emit_pcapng_with_dsb = PCAP._emit_pcapng_with_dsb.__get__(stub)
    # _write_minimal_pcapng_with_keys is a @staticmethod on PCAP; expose
    # it on the stub so the bound _emit_pcapng_with_dsb's `self.helper(...)`
    # resolves correctly.
    stub._write_minimal_pcapng_with_keys = PCAP._write_minimal_pcapng_with_keys
    return stub


def _is_valid_pcapng_with_keys(path: str, *, expect_keys: bool) -> bool:
    """Quick structural check: file starts with SHB magic and contains
    DSB block when expected. Avoids depending on a full pcapng parser."""
    if not os.path.exists(path) or os.path.getsize(path) < 28:
        return False
    with open(path, "rb") as f:
        head = f.read(28)
    # Section Header Block: type=0x0A0D0D0A
    if struct.unpack("<I", head[0:4])[0] != 0x0A0D0D0A:
        return False
    if not expect_keys:
        return True
    with open(path, "rb") as f:
        body = f.read()
    # Decryption Secrets Block: type=0x0000000A
    return struct.pack("<I", 0x0000000A) in body


class TestDsbGuardMissingSource:
    def test_missing_source_writes_minimal_pcapng_with_keys(self, tmp_path, caplog):
        out = tmp_path / "out.pcapng"
        missing = tmp_path / "does-not-exist.pcap"
        emitter = _make_stub_emitter(str(out))
        keys = [
            "CLIENT_RANDOM 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef "
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        ]
        with caplog.at_level(logging.WARNING, logger="test_dsb_guard"):
            emitter._emit_pcapng_with_dsb(str(missing), str(out), keys)
        assert out.exists(), "guard must produce an output file even on missing source"
        assert _is_valid_pcapng_with_keys(str(out), expect_keys=True), (
            "minimal pcapng must include SHB+IDB+DSB"
        )
        # Surface the diagnostic so the user can see why the file is empty.
        assert any("missing or empty" in r.getMessage() for r in caplog.records)

    def test_missing_source_no_keys_writes_minimal_pcapng_without_dsb(self, tmp_path):
        out = tmp_path / "out.pcapng"
        missing = tmp_path / "missing.pcap"
        emitter = _make_stub_emitter(str(out))
        emitter._emit_pcapng_with_dsb(str(missing), str(out), [])
        assert out.exists()
        assert _is_valid_pcapng_with_keys(str(out), expect_keys=False)


class TestDsbGuardEmptySource:
    def test_zero_byte_source_writes_minimal_pcapng_with_keys(self, tmp_path):
        out = tmp_path / "out.pcapng"
        empty = tmp_path / "empty.pcap"
        empty.write_bytes(b"")  # zero bytes
        emitter = _make_stub_emitter(str(out))
        emitter._emit_pcapng_with_dsb(
            str(empty), str(out), ["CLIENT_RANDOM " + "ab" * 32 + " " + "cd" * 48],
        )
        assert out.exists()
        assert _is_valid_pcapng_with_keys(str(out), expect_keys=True)


class TestDsbGuardCorruptSource:
    def test_truncated_pcap_falls_back_to_keys_only(self, tmp_path, caplog):
        out = tmp_path / "out.pcapng"
        # Write only a partial pcap header (24 bytes is the full classic
        # libpcap header; 12 bytes is mid-header — truncated).
        truncated = tmp_path / "truncated.pcap"
        truncated.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00")
        emitter = _make_stub_emitter(str(out))
        keys = ["CLIENT_RANDOM " + "11" * 32 + " " + "22" * 48]
        with caplog.at_level(logging.WARNING, logger="test_dsb_guard"):
            # Must not raise even with garbage input.
            emitter._emit_pcapng_with_dsb(str(truncated), str(out), keys)
        # Either the warning ("missing or empty" — for size-0/missing) or
        # the error ("PCAPNG finalization failed reading") must have been
        # logged, depending on which guard arm fired. Both produce a
        # usable keys-bearing output.
        assert out.exists()
        assert _is_valid_pcapng_with_keys(str(out), expect_keys=True)


class TestDsbGuardHappyPathStillWorks:
    def test_valid_source_emits_full_pcapng(self, tmp_path):
        # Build a valid 1-packet pcap to feed the happy path.
        try:
            from scapy.all import Ether, IP, TCP, wrpcap
        except ImportError:
            pytest.skip("scapy not installed")
        src = tmp_path / "valid.pcap"
        out = tmp_path / "valid_out.pcapng"
        pkt = Ether() / IP(dst="1.1.1.1") / TCP(dport=443)
        wrpcap(str(src), [pkt])
        emitter = _make_stub_emitter(str(out))
        emitter._emit_pcapng_with_dsb(str(src), str(out), [])
        assert out.exists()
        # Happy path: SHB + IDB + EPB(s) — the EPB block type is 0x06.
        body = out.read_bytes()
        # EPB type marker
        assert struct.pack("<I", 0x00000006) in body, "expected an EPB in happy-path output"
