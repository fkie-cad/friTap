"""The ``chromium-internal`` attribution bucket: an unattributed
Chromium-family flow to a ``chromium_internal_hosts`` host
(friTap/flow/attribution.py ``chromium_internal_update`` + FlowCollector)."""

from __future__ import annotations

from types import SimpleNamespace

from friTap.events import DatalogEvent, RequestContextEvent
from friTap.flow.attribution import (
    BUCKET_CHROMIUM_INTERNAL,
    chromium_internal_candidate,
    chromium_internal_host_update,
    chromium_internal_update,
    merge_attribution,
)
from friTap.flow.collector import FlowCollector

FB = {"sdk": "Facebook SDK", "vendor": "Meta", "category": "social"}
INTERNAL_HOST = "safebrowsing.googleapis.com"


def _request(host=INTERNAL_HOST, library="libmonochrome.so", t=100.0, path="/v4/x"):
    return DatalogEvent(
        data=f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode(),
        function="SSL_write", direction="write", library=library,
        src_addr="10.0.0.2", src_port=51000, dst_addr="142.250.0.1", dst_port=443,
        ssl_session_id="", timestamp=t)


def _response(t=100.5):
    return DatalogEvent(
        data=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        function="SSL_read", direction="read", library="libmonochrome.so",
        src_addr="142.250.0.1", src_port=443, dst_addr="10.0.0.2", dst_port=51000,
        ssl_session_id="", timestamp=t)


def _only_flow(collector):
    flows = collector.get_flows()
    assert len(flows) == 1
    return flows[0]


def _bucket(flow):
    return (flow.attribution or {}).get("bucket")


# --- collector ---------------------------------------------------------------

def test_webview_flow_to_internal_host_without_originator_is_bucketed():
    collector = FlowCollector()
    collector.on_data(_request())
    flow = _only_flow(collector)
    assert flow.attribution["transport"]["kind"] == "webview"
    assert _bucket(flow) == BUCKET_CHROMIUM_INTERNAL
    assert "originator" not in flow.attribution


def test_chrome_flow_with_port_in_host_is_bucketed():
    collector = FlowCollector()
    collector.set_capture_target("com.android.chrome")
    collector.on_data(_request(host="Update.GoogleAPIs.com:443"))
    flow = _only_flow(collector)
    assert flow.attribution["transport"]["kind"] == "chrome"
    assert _bucket(flow) == BUCKET_CHROMIUM_INTERNAL


def test_bucket_is_on_the_notified_flow():
    collector = FlowCollector()
    seen = []
    collector.subscribe(lambda flow, event_type: seen.append(_bucket(flow)))
    collector.on_data(_request())
    assert seen and seen[0] == BUCKET_CHROMIUM_INTERNAL


def test_flow_with_originator_gets_no_bucket():
    collector = FlowCollector()
    collector.on_request_context(RequestContextEvent(
        event="start", req_id="r1", timestamp=100.0, method="GET",
        url=f"https://{INTERNAL_HOST}/v4/x",
        frames=["com.facebook.GraphRequest.execute"], stack_kind="cronet"))
    collector.on_data(_request(t=100.2))
    flow = _only_flow(collector)
    assert flow.attribution["originator"]["sdk"] == "Facebook SDK"
    assert _bucket(flow) is None


def test_non_chromium_transport_gets_no_bucket():
    collector = FlowCollector()
    collector.on_data(_request(library="libssl.so"))
    flow = _only_flow(collector)
    assert flow.attribution["transport"]["kind"] not in {"webview", "chrome"}
    assert _bucket(flow) is None


def test_unknown_host_gets_no_bucket():
    collector = FlowCollector()
    collector.on_data(_request(host="api.example.com"))
    assert _bucket(_only_flow(collector)) is None


def test_flush_buckets_completed_flows():
    collector = FlowCollector()
    collector.on_data(_request())
    collector.on_data(_response())
    collector.flush()
    flows = collector.get_flows()
    assert flows and all(_bucket(flow) == BUCKET_CHROMIUM_INTERNAL for flow in flows)


# --- chromium_internal_update / merge_attribution ------------------------------

def _flow(kind="webview", sdk=None, **attribution):
    return SimpleNamespace(sdk=sdk, attribution={"transport": {"module": "m", "kind": kind},
                                                 **attribution})


def test_update_rules():
    assert chromium_internal_update(_flow(), INTERNAL_HOST) == {"bucket": BUCKET_CHROMIUM_INTERNAL}
    for kind in ("chrome", "cronet", "gms-cronet", "httpengine", "electron", "cef"):
        assert chromium_internal_update(_flow(kind), INTERNAL_HOST), kind
    assert chromium_internal_update(_flow("flutter"), INTERNAL_HOST) is None
    assert chromium_internal_update(_flow(), "") is None
    assert chromium_internal_update(_flow(), "example.com") is None
    assert chromium_internal_update(_flow(sdk=dict(FB)), INTERNAL_HOST) is None
    assert chromium_internal_update(_flow(originator=dict(FB)), INTERNAL_HOST) is None
    assert chromium_internal_update(_flow(bucket="cache"), INTERNAL_HOST) is None
    assert chromium_internal_update(SimpleNamespace(attribution=None), INTERNAL_HOST) is None


def test_candidate_rules_need_no_host():
    assert chromium_internal_candidate(_flow())
    assert not chromium_internal_candidate(_flow("flutter"))
    assert not chromium_internal_candidate(_flow(sdk=dict(FB)))
    assert not chromium_internal_candidate(_flow(originator=dict(FB)))
    assert not chromium_internal_candidate(_flow(bucket="cache"))


def test_collector_skips_the_host_lookup_for_a_rejected_flow(monkeypatch):
    """Cheap rejects come first: a non-Chromium flow never computes its host."""
    collector = FlowCollector()
    hosts = []
    real = collector._flow_host
    monkeypatch.setattr(collector, "_flow_host", lambda flow: hosts.append(1) or real(flow))
    collector.on_data(_request(library="libssl.so"))
    assert hosts == []
    collector.on_data(_request(library="libmonochrome.so", path="/v4/y"))
    assert hosts


def test_collector_skips_the_host_lookup_for_non_candidates_after_chromium_was_seen(monkeypatch):
    collector = FlowCollector()
    collector.on_data(_request())  # Chromium transport seen
    hosts = []
    real = collector._flow_host
    monkeypatch.setattr(collector, "_flow_host", lambda flow: hosts.append(1) or real(flow))
    other = _request(library="libssl.so", path="/a")
    other.src_port = 52000
    collector.on_data(other)
    assert hosts == []


def test_host_update_rules():
    assert chromium_internal_host_update(INTERNAL_HOST) == {"bucket": BUCKET_CHROMIUM_INTERNAL}
    assert chromium_internal_host_update("") is None
    assert chromium_internal_host_update("example.com") is None


def test_bucket_follows_a_late_sni():
    """Every notify path runs the bucket pass, e.g. TLS metadata stamped later."""
    from friTap.events import SESSION_STARTED, SessionEvent
    collector = FlowCollector()
    event = _request()
    event.data = b"GET /v4/x HTTP/1.0\r\n\r\n"  # no Host: the SNI is the host
    collector.on_data(event)
    flow = _only_flow(collector)
    assert _bucket(flow) is None
    seen = []
    collector.subscribe(lambda notified, event_type: seen.append(_bucket(notified)))
    collector.on_session_event(SessionEvent(
        event_type=SESSION_STARTED, connection_id=flow.connection_id,
        server_name=INTERNAL_HOST))
    assert _bucket(_only_flow(collector)) == BUCKET_CHROMIUM_INTERNAL
    assert seen == [BUCKET_CHROMIUM_INTERNAL]


def test_later_originator_drops_the_chromium_internal_bucket():
    bucketed = {"transport": {"module": "m", "kind": "webview"}, "bucket": BUCKET_CHROMIUM_INTERNAL}
    claim = {"originator": dict(FB), "source": "java-request", "confidence": "high"}
    merged = merge_attribution(bucketed, claim)
    assert merged["originator"] == FB and "bucket" not in merged
    # never filled onto a flow that already has an originator
    assert "bucket" not in merge_attribution(claim, {"bucket": BUCKET_CHROMIUM_INTERNAL})
    # other buckets are untouched by an originator
    assert merge_attribution({"bucket": "cache"}, claim)["bucket"] == "cache"
