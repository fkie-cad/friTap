"""Tests for server-port attribution and keylog-path wiring in ``PCAP``.

Covers three fixes:

* #18 — ``_record_server_port`` must pick the SERVER side of the 4-tuple by
  *direction* (source on a READ, destination on a WRITE), independent of
  transport, so UDP/QUIC reads record the remote QUIC server port, not the
  local client port.
* #53 — ``_seed_server_ports_from_sockets`` honors a transport hint when the
  socket dict provides one.
* #41 — ``keylog_path`` set on the pcap object flows into the manifest dict.

The full ``PCAP.__init__`` spins threads in full-capture mode, so we follow
the stub pattern from ``test_pcap_dsb_defensive`` and bind the unbound methods
to a minimal namespace instead.
"""

import json
import logging
import time
import types

from friTap.constants import SSL_READ, SSL_WRITE  # noqa: E402
from friTap.pcap import PCAP  # noqa: E402


def _make_stub(pcap_file_name="capture.pcap"):
    """Minimal stub exposing the methods under test, bound to it."""
    stub = types.SimpleNamespace()
    stub.pcap_file_name = pcap_file_name
    stub.logger = logging.getLogger("test_server_port")
    stub.SSL_READ = SSL_READ
    stub.SSL_WRITE = SSL_WRITE
    stub._observed_server_ports = {"tcp": set(), "udp": set()}
    stub.keylog_path = None
    stub._record_server_port = PCAP._record_server_port.__get__(stub)
    stub._seed_server_ports_from_sockets = \
        PCAP._seed_server_ports_from_sockets.__get__(stub)
    stub._write_capture_manifest = PCAP._write_capture_manifest.__get__(stub)
    _bind_pcap_staticmethods(stub)
    return stub


def _bind_pcap_staticmethods(stub):
    """Expose every PCAP staticmethod (e.g. ``_keylog_with_content``) on the
    stub, so a new helper used by a bound method cannot silently break it."""
    for name, attr in vars(PCAP).items():
        if isinstance(attr, staticmethod):
            setattr(stub, name, attr.__func__)


class TestRecordServerPort:
    def test_udp_quic_read_records_server_source_port(self):
        """#18: a UDP/QUIC READ must record the SERVER (source) port, 443,
        not the local client port 51234."""
        stub = _make_stub()
        read_fn = next(iter(SSL_READ))
        stub._record_server_port("udp", read_fn, src_port=443, dst_port=51234)
        assert stub._observed_server_ports["udp"] == {443}
        # Must not have leaked into the TCP bucket or recorded the client port.
        assert stub._observed_server_ports["tcp"] == set()

    def test_udp_quic_write_records_server_dest_port(self):
        """#18: a UDP/QUIC WRITE must record the SERVER (destination) port."""
        stub = _make_stub()
        write_fn = next(iter(SSL_WRITE))
        stub._record_server_port("udp", write_fn, src_port=51234, dst_port=443)
        assert stub._observed_server_ports["udp"] == {443}
        assert stub._observed_server_ports["tcp"] == set()

    def test_tcp_read_records_server_source_port(self):
        """Direction logic is unchanged for TCP reads (source is the server)."""
        stub = _make_stub()
        read_fn = next(iter(SSL_READ))
        stub._record_server_port("tcp", read_fn, src_port=443, dst_port=51234)
        assert stub._observed_server_ports["tcp"] == {443}
        assert stub._observed_server_ports["udp"] == set()

    def test_tcp_write_records_server_dest_port(self):
        stub = _make_stub()
        write_fn = next(iter(SSL_WRITE))
        stub._record_server_port("tcp", write_fn, src_port=51234, dst_port=443)
        assert stub._observed_server_ports["tcp"] == {443}


class TestSeedServerPortsFromSockets:
    def test_udp_hint_routes_to_udp_bucket(self):
        """#53: an explicit transport hint is honored for bucketing."""
        stub = _make_stub()
        stub._seed_server_ports_from_sockets(
            [{"dst_port": 443, "protocol": "udp"}])
        assert stub._observed_server_ports["udp"] == {443}
        assert stub._observed_server_ports["tcp"] == set()

    def test_no_hint_defaults_to_tcp(self):
        """Documented fallback: no transport hint -> TCP bucket."""
        stub = _make_stub()
        stub._seed_server_ports_from_sockets([{"dst_port": 8443}])
        assert stub._observed_server_ports["tcp"] == {8443}


class TestKeylogManifest:
    def test_keylog_path_flows_into_manifest(self, tmp_path):
        """#41: keylog_path set on the pcap object lands in the manifest dict."""
        out = tmp_path / "capture.pcap"
        keys = tmp_path / "keys.log"
        keys.write_text("CLIENT_RANDOM abc 123\n")  # a real, written keylog
        stub = _make_stub(pcap_file_name=str(out))
        stub.keylog_path = str(keys)
        stub._observed_server_ports["tcp"].add(443)

        stub._write_capture_manifest()

        manifest_path = f"{out}.fritap.json"
        with open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
        assert manifest["keylog"] == str(tmp_path / "keys.log")
        assert manifest["tls_ports"] == [443]

    def test_no_keylog_omits_branch(self, tmp_path):
        out = tmp_path / "capture.pcap"
        stub = _make_stub(pcap_file_name=str(out))
        stub._write_capture_manifest()
        with open(f"{out}.fritap.json", encoding="utf-8") as fh:
            manifest = json.load(fh)
        assert "keylog" not in manifest

    # -- Defect 1: the manifest must not name a phantom/wrong TLS keylog ------
    def test_manifest_prefers_base_keylog_over_phantom_split(self, tmp_path):
        """DEFECT-1: ``--protocol tls,rc4 -k <base>.keylog`` splits into
        active_keylogs={tls:<base>.tls.keylog, rc4:<base>.rc4.keylog}. On Windows the
        target's TLS is SChannel, so ``<base>.tls.keylog`` is NEVER written and the
        real TLS secrets go to the BASE ``<base>.keylog`` (separate LSASS session).
        ``self.keylog_path`` is the LAST handler's split (``<base>.rc4.keylog``). The
        manifest must name the base keylog and drop the phantom ``.tls`` split."""
        out = tmp_path / "capture.pcap"
        base = tmp_path / "base.keylog"
        base.write_text("CLIENT_RANDOM abc 123\n")   # real TLS secrets (LSASS)
        rc4 = tmp_path / "base.rc4.keylog"
        rc4.write_text("RC4_KEY deadbeef\n")          # real rc4 split
        phantom_tls = tmp_path / "base.tls.keylog"    # never written on Windows
        stub = _make_stub(pcap_file_name=str(out))
        stub.base_keylog_path = str(base)
        stub._session_started_at = time.time() - 1
        stub.keylog_path = str(rc4)                    # last-handler split wins here
        stub.active_keylogs = {"tls": str(phantom_tls), "rc4": str(rc4)}

        stub._write_capture_manifest()

        with open(f"{out}.fritap.json", encoding="utf-8") as fh:
            manifest = json.load(fh)
        # Generic "keylog" resolves to the base file that actually holds TLS keys.
        assert manifest["keylog"] == str(base)
        # The per-protocol map keeps the real rc4 split and points "tls" at the base,
        # never at the phantom split path.
        assert manifest["keylogs"]["rc4"] == str(rc4)
        assert manifest["keylogs"]["tls"] == str(base)
        assert str(phantom_tls) not in manifest["keylogs"].values()

    def test_manifest_omits_keylog_when_nothing_written(self, tmp_path):
        """DEFECT-1: when neither the split nor the base keylog was ever written,
        the manifest omits the keylog fields entirely instead of recording a
        phantom path a consumer would fail to open."""
        out = tmp_path / "capture.pcap"
        stub = _make_stub(pcap_file_name=str(out))
        stub.base_keylog_path = str(tmp_path / "base.keylog")      # never written
        stub._session_started_at = time.time() - 1
        stub.keylog_path = str(tmp_path / "base.rc4.keylog")       # never written
        stub.active_keylogs = {
            "tls": str(tmp_path / "base.tls.keylog"),
            "rc4": str(tmp_path / "base.rc4.keylog"),
        }

        stub._write_capture_manifest()

        with open(f"{out}.fritap.json", encoding="utf-8") as fh:
            manifest = json.load(fh)
        assert "keylog" not in manifest
        assert "keylogs" not in manifest

    def test_manifest_single_protocol_output_unchanged(self, tmp_path):
        """DEFECT-1: a single-protocol capture (no split, no base fallback) is
        byte-for-byte unchanged — the generic keylog is still self.keylog_path and
        no per-protocol "keylogs" map appears."""
        out = tmp_path / "capture.pcap"
        keys = tmp_path / "keys.log"
        keys.write_text("CLIENT_RANDOM abc 123\n")
        stub = _make_stub(pcap_file_name=str(out))
        stub.keylog_path = str(keys)
        stub._session_started_at = time.time() - 1
        stub._observed_server_ports["tcp"].add(443)

        stub._write_capture_manifest()

        with open(f"{out}.fritap.json", encoding="utf-8") as fh:
            manifest = json.load(fh)
        assert manifest["keylog"] == str(keys)
        assert manifest["tls_ports"] == [443]
        assert "keylogs" not in manifest


def _bind_known_port_methods(stub):
    """Bind the explicit-port seeding methods onto an existing stub."""
    stub._add_known_server_ports = PCAP._add_known_server_ports.__get__(stub)
    stub.set_known_tls_ports = PCAP.set_known_tls_ports.__get__(stub)
    stub.set_known_quic_ports = PCAP.set_known_quic_ports.__get__(stub)
    return stub


class TestKnownServerPorts:
    """Defect 3: a non-standard TLS server port (e.g. 8443) must reach the
    manifest's ``tls_ports`` so the offline Decode-As / nested-RC4 pipeline can
    recover streams. Covers both seeding routes: a traced socket dict and an
    explicit capture-time ``--tls-port``/``--quic-port``."""

    def test_socket_dict_seeds_nonstandard_tls_port_into_manifest(self, tmp_path):
        """A traced socket with dst_port 8443 lands in manifest tls_ports."""
        out = tmp_path / "capture.pcap"
        stub = _make_stub(pcap_file_name=str(out))
        stub._seed_server_ports_from_sockets([{"dst_port": 8443}])
        stub._write_capture_manifest()
        with open(f"{out}.fritap.json", encoding="utf-8") as fh:
            manifest = json.load(fh)
        assert manifest["tls_ports"] == [8443]

    def test_set_known_tls_ports_appears_in_manifest(self, tmp_path):
        """An explicit capture-time --tls-port lands in manifest tls_ports."""
        out = tmp_path / "capture.pcap"
        stub = _bind_known_port_methods(_make_stub(pcap_file_name=str(out)))
        stub.set_known_tls_ports([8443])
        stub._write_capture_manifest()
        with open(f"{out}.fritap.json", encoding="utf-8") as fh:
            manifest = json.load(fh)
        assert manifest["tls_ports"] == [8443]

    def test_set_known_quic_ports_appears_in_manifest(self, tmp_path):
        """An explicit capture-time --quic-port lands in manifest quic_ports."""
        out = tmp_path / "capture.pcap"
        stub = _bind_known_port_methods(_make_stub(pcap_file_name=str(out)))
        stub.set_known_quic_ports([8443])
        stub._write_capture_manifest()
        with open(f"{out}.fritap.json", encoding="utf-8") as fh:
            manifest = json.load(fh)
        assert manifest["quic_ports"] == [8443]

    def test_unset_ports_are_side_effect_free(self):
        """Best-effort: empty/None input must not touch the observed-port sets."""
        stub = _bind_known_port_methods(_make_stub())
        stub.set_known_tls_ports(None)
        stub.set_known_tls_ports([])
        stub.set_known_quic_ports(None)
        assert stub._observed_server_ports["tcp"] == set()
        assert stub._observed_server_ports["udp"] == set()

    def test_invalid_ports_are_skipped(self):
        """Non-int / non-positive ports are dropped, valid ones kept."""
        stub = _bind_known_port_methods(_make_stub())
        stub.set_known_tls_ports(["8443", "bad", 0, -1, 9000])
        assert stub._observed_server_ports["tcp"] == {8443, 9000}
