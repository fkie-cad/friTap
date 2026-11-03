"""CredentialAnalyzer keeps per-flow entropy state per call, not per instance.

One analyzer instance is shared across flows (pipelines, the TUI, threads).
Its per-flow entropy de-noising state (the dedup set and the suppressed
counter) must not leak between flows, even when a second flow is analysed
while the first one is still in progress (re-entrant or concurrent use).

Pure Python: no device, Frida or tshark.
"""

import json
import threading

from friTap.analysis.credentials import CredentialAnalyzer
from friTap.flow.models import Flow, FlowState
from friTap.parsers.base import ParseResult

# A high-entropy value with no clean decode, so it yields a LOW finding.
_SHARED_SECRET = "Zq9XvL2pWm7Kd4Rn8Tf6Yh1Bc3Js5Gv0Ae2Wq8Lo4Pi6Un"
_UUIDS_A = [
    "0f8fad5b-d9cb-469f-a165-70867728950e",
    "7c9e6679-7425-40de-944b-e07fc1f90ae7",
]
_UUIDS_B = [
    "16fd2706-8baf-433b-82eb-8c7fada847da",
    "886313e1-3b8a-5372-9b90-0c9aee199e5d",
    "a8098c1a-f86e-11da-bd1a-00112444be1e",
]


def _json_flow(flow_id: str, payload: dict) -> Flow:
    flow = Flow(
        flow_id=flow_id,
        connection_id=f"conn-{flow_id}",
        src_addr="10.0.0.2",
        src_port=51000,
        dst_addr="93.184.216.34",
        dst_port=443,
        state=FlowState.COMPLETE,
        started=1000.0,
        ended=1001.0,
    )
    flow.request = ParseResult(
        protocol="HTTP/1.1",
        method="POST",
        url="/upload",
        host=f"{flow_id}.example.com",
        headers={"Host": f"{flow_id}.example.com", "Content-Type": "application/json"},
        body=json.dumps(payload).encode(),
        content_type="application/json",
        is_request=True,
        is_complete=True,
    )
    return flow


def _flow_a() -> Flow:
    payload = {f"id{i}": value for i, value in enumerate(_UUIDS_A)}
    payload["api_signature"] = _SHARED_SECRET
    return _json_flow("flow-a", payload)


def _flow_b() -> Flow:
    payload = {f"ref{i}": value for i, value in enumerate(_UUIDS_B)}
    payload["request_signature"] = _SHARED_SECRET
    return _json_flow("flow-b", payload)


def _comparable(findings):
    """Findings without the creation timestamp (differs between runs)."""
    return [
        (f.severity, f.title, f.description, f.source, f.flow_id,
         f.confidence, f.evidence, f.metadata)
        for f in findings
    ]


def _analysed_separately():
    analyzer = CredentialAnalyzer()
    return (_comparable(analyzer.analyze_flow(_flow_a())),
            _comparable(analyzer.analyze_flow(_flow_b())))


def _nest_inside_body_read(flow: Flow, nested) -> None:
    """Run *nested* once when the analyzer reads *flow*'s request body.

    The analyzer reads the body after it has set up the flow's state but
    before any check runs, so *nested* runs in the middle of the outer
    ``analyze_flow`` call.
    """
    original = flow.get_decompressed_request_body

    def read_body_and_run_nested():
        nested()
        return original()

    flow.get_decompressed_request_body = read_body_and_run_nested


def test_baseline_flows_exercise_shared_entropy_state():
    """Each flow suppresses its UUIDs and reports the shared secret."""
    results_a, results_b = _analysed_separately()
    for results, uuid_count in ((results_a, len(_UUIDS_A)), (results_b, len(_UUIDS_B))):
        titles = [entry[1] for entry in results]
        assert "High-entropy string (potential secret)" in titles
        summary = [entry for entry in results if entry[1].startswith("Entropy scan suppressed")]
        assert summary and summary[0][6]["suppressed"] == uuid_count


def test_reentrant_flows_match_separate_analysis():
    expected_a, expected_b = _analysed_separately()
    analyzer = CredentialAnalyzer()
    flow_a, nested_results = _flow_a(), []
    _nest_inside_body_read(
        flow_a, lambda: nested_results.append(analyzer.analyze_flow(_flow_b())))

    results_a = _comparable(analyzer.analyze_flow(flow_a))

    assert results_a == expected_a
    assert _comparable(nested_results[0]) == expected_b


def test_concurrent_flows_match_separate_analysis():
    """Two threads interleave inside one shared analyzer instance."""
    expected_a, expected_b = _analysed_separately()
    analyzer = CredentialAnalyzer()
    flow_a, flow_b = _flow_a(), _flow_b()
    both_started = threading.Barrier(2, timeout=5)
    for flow in (flow_a, flow_b):
        _nest_inside_body_read(flow, both_started.wait)
    results = {}

    def analyse(name, flow):
        results[name] = _comparable(analyzer.analyze_flow(flow))

    threads = [threading.Thread(target=analyse, args=("a", flow_a)),
               threading.Thread(target=analyse, args=("b", flow_b))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert results == {"a": expected_a, "b": expected_b}
