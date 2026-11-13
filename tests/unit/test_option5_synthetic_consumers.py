"""Option 5 consumers: synthetic 198.18.0.0/15 endpoints are flagged or skipped.

Covers the JSON / JSONL data records, the digest (flow meta, endpoint rows,
host fallback), the HAR export, the IOC destination-IP check and the legacy
verbose message handler for an address-less datalog record.
"""

from __future__ import annotations

import io
import json
import logging
from types import SimpleNamespace
from unittest.mock import MagicMock

from friTap.analysis.digest import _Aggregator, _flow_host, protocol_sections
from friTap.analysis.digest_flow import _flow_meta
from friTap.analysis.export_har import flow_to_har_entry
from friTap.analysis.ioc import IocAnalyzer
from friTap.events import DatalogEvent
from friTap.output.json_handler import JsonOutputHandler
from friTap.output.jsonl_handler import JsonlOutputHandler
from friTap.output.jsonl_stdout_handler import JsonlStdoutHandler
from tests.unit._digest_helpers import http_flow

SYNTHETIC_CLIENT = "198.18.12.34"
SYNTHETIC_SERVER = "198.19.56.78"


def _datalog(synthetic: bool) -> DatalogEvent:
    return DatalogEvent(
        timestamp=1.0, data=b"hi", function="SSL_write", direction="write",
        src_addr=SYNTHETIC_CLIENT if synthetic else "10.0.0.1", src_port=50000,
        dst_addr=SYNTHETIC_SERVER if synthetic else "10.0.0.2", dst_port=443,
        endpoints_synthetic=synthetic)


def _synthetic_flow(flow_id="s1", *, host="", flag=True):
    flow = http_flow(flow_id, host=host)
    flow.src_addr, flow.dst_addr = SYNTHETIC_CLIENT, SYNTHETIC_SERVER
    flow.endpoints_synthetic = flag
    if not host:
        flow.request.host = ""
        flow.request.headers.pop("host", None)
    return flow


# --------------------------------------------------------------------------
# JSON / JSONL data records
# --------------------------------------------------------------------------

def test_json_connection_record_carries_endpoints_synthetic(tmp_path):
    path = str(tmp_path / "out.json")
    handler = JsonOutputHandler(path, session_info={})
    handler.setup(MagicMock())
    handler.on_data(_datalog(True))
    handler.on_data(_datalog(False))
    handler.close()
    connections = json.loads((tmp_path / "out.json").read_text())["connections"]
    assert [c["endpoints_synthetic"] for c in connections] == [True, False]


def test_jsonl_file_record_carries_endpoints_synthetic():
    handler = JsonlOutputHandler("unused.jsonl")
    synthetic = handler._build_record(_datalog(True))
    real = handler._build_record(_datalog(False))
    assert synthetic["endpoints_synthetic"] is True
    assert "synthetic_endpoints" not in synthetic  # no legacy alias
    assert real["endpoints_synthetic"] is False


def test_jsonl_stdout_data_record_carries_endpoints_synthetic():
    buffer = io.StringIO()
    handler = JsonlStdoutHandler(stream=buffer)
    handler.setup(MagicMock())
    handler._on_any_event(_datalog(True))
    records = [json.loads(line) for line in buffer.getvalue().splitlines()]
    data = [r for r in records if r.get("type") == "data"]
    assert data and data[0]["endpoints_synthetic"] is True


# --------------------------------------------------------------------------
# Digest
# --------------------------------------------------------------------------

def test_flow_meta_flags_synthetic_endpoints():
    assert _flow_meta(_synthetic_flow(), 1)["endpoints_synthetic"] is True


def test_flow_meta_flags_synthetic_address_without_flag():
    assert _flow_meta(_synthetic_flow(flag=False), 1)["endpoints_synthetic"] is True


def test_flow_meta_omits_flag_for_real_endpoints():
    assert "endpoints_synthetic" not in _flow_meta(http_flow("r1"), 1)


def test_endpoint_rows_carry_flag_only_when_synthetic():
    agg = _Aggregator()
    agg.add_flow(_synthetic_flow(host="synthetic.example"), 100, 1)
    agg.add_flow(http_flow("r1", host="real.example"), 100, 2)
    rows = {row["untrusted"]["host"]: row
            for section in protocol_sections(agg).values() for row in section["endpoints"]}
    assert rows["synthetic.example"]["endpoints_synthetic"] is True
    assert "endpoints_synthetic" not in rows["real.example"]


def test_host_fallback_skips_synthetic_addresses():
    host = _flow_host(_synthetic_flow())
    assert "198.18." not in host and "198.19." not in host
    assert host == "?"


def test_host_fallback_still_uses_real_address():
    flow = http_flow("r1", host="")
    flow.request.host = ""
    assert _flow_host(flow) == "93.184.216.34"


# --------------------------------------------------------------------------
# HAR / IOC
# --------------------------------------------------------------------------

def test_har_omits_server_ip_for_flagged_flow():
    assert "serverIPAddress" not in flow_to_har_entry(_synthetic_flow(host="a.example"))


def test_har_omits_server_ip_for_synthetic_address_without_flag():
    entry = flow_to_har_entry(_synthetic_flow(host="a.example", flag=False))
    assert "serverIPAddress" not in entry


def test_har_keeps_real_server_ip():
    assert flow_to_har_entry(http_flow("r1"))["serverIPAddress"] == "93.184.216.34"


def _destination_ip_findings(flow):
    findings = IocAnalyzer(include_private_ips=True).analyze_flow(flow)
    return [f for f in findings if f.evidence.get("direction") == "destination"]


def test_ioc_skips_synthetic_destination_even_with_private_ips():
    assert _destination_ip_findings(_synthetic_flow(host="a.example")) == []


def test_ioc_still_reports_real_destination():
    assert len(_destination_ip_findings(http_flow("r1"))) == 1


def test_ioc_skips_flagged_flow_with_unrecognised_destination():
    # The flag alone marks the tuple synthetic (shared predicate with HAR/digest).
    flow = http_flow("f1")
    flow.endpoints_synthetic = True
    assert _destination_ip_findings(flow) == []


def test_har_treats_synthetic_client_as_synthetic():
    flow = http_flow("c1", host="a.example")
    flow.src_addr = SYNTHETIC_CLIENT
    assert "serverIPAddress" not in flow_to_har_entry(flow)


# --------------------------------------------------------------------------
# Legacy verbose message handler
# --------------------------------------------------------------------------

def _verbose_legacy_logger():
    return SimpleNamespace(
        logger=logging.getLogger("test.legacy.option5"), debug=False, debug_output=False,
        verbose=True, keylog=False, json_output=False, pcap_name=None, live=False,
        full_capture=False, socket_trace=False)


def test_legacy_verbose_handles_address_less_datalog():
    from friTap.legacy.message_handler import handle_message_legacy

    payload = {"contentType": "datalog", "function": "SSL_write", "ssl_session_id": "sid"}
    inst = _verbose_legacy_logger()
    handle_message_legacy(inst, payload, b"plaintext", {"payload": payload})


def test_legacy_verbose_socket_trace_handles_address_less_datalog():
    from friTap.legacy.message_handler import handle_message_legacy

    payload = {"contentType": "datalog", "function": "SSL_read"}
    inst = _verbose_legacy_logger()
    inst.socket_trace = True
    inst.traced_Socket_Set, inst.traced_scapy_socket_Set = set(), set()
    handle_message_legacy(inst, payload, b"plaintext", {"payload": payload})
    assert len(inst.traced_Socket_Set) == 1


def test_legacy_pcap_skips_address_less_datalog():
    from friTap.legacy.message_handler import handle_message_legacy

    written = []
    payload = {"contentType": "datalog", "function": "SSL_write"}
    inst = _verbose_legacy_logger()
    inst.pcap_name = "plain.pcap"
    inst.pcap_obj = SimpleNamespace(log_plaintext_payload=lambda *a, **k: written.append(a))
    handle_message_legacy(inst, payload, b"plaintext", {"payload": payload})
    assert written == []


def test_legacy_pcap_writes_addressed_datalog():
    from friTap.legacy.message_handler import handle_message_legacy

    written = []
    payload = {"contentType": "datalog", "function": "SSL_write", "ss_family": "AF_INET",
               "src_addr": 0x0A000001, "src_port": 40000, "dst_addr": 0x0A000002,
               "dst_port": 443}
    inst = _verbose_legacy_logger()
    inst.pcap_name = "plain.pcap"
    inst.pcap_obj = SimpleNamespace(log_plaintext_payload=lambda *a, **k: written.append(a))
    handle_message_legacy(inst, payload, b"plaintext", {"payload": payload})
    assert written and written[0][0] == "AF_INET" and written[0][2:6] == (
        0x0A000001, 40000, 0x0A000002, 443)
