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
import types

from friTap.constants import SSL_READ, SSL_WRITE
from friTap.pcap import PCAP


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
    return stub


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
        stub = _make_stub(pcap_file_name=str(out))
        stub.keylog_path = str(tmp_path / "keys.log")
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
