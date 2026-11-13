"""Host join of Java request contexts onto flows (friTap/flow/request_context_join.py)
and its FlowCollector / .tap integration (``--attribute-sdk``)."""

from __future__ import annotations

from friTap.events import DatalogEvent, RequestContextEvent
from friTap.flow import collector as collector_module
from friTap.flow import request_context_join as join
from friTap.flow.collector import FlowCollector
from friTap.flow.request_context_join import (
    RequestContextStore,
    absolute_request_url,
    normalize_request_key,
)
from friTap.flow.tap_reader import TapReader
from friTap.flow.tap_writer import TapWriter

FB = {"sdk": "Facebook SDK", "vendor": "Meta", "category": "social"}
AF = {"sdk": "AppsFlyer", "vendor": "AppsFlyer", "category": "attribution"}
FB_FRAMES = ["org.chromium.net.UrlRequest.start", "com.facebook.GraphRequest.execute"]
AF_FRAMES = ["com.appsflyer.internal.AFa1.run"]
URL = "https://example.com/api?x=1"
KEY = ("GET", "https://example.com/api?x=1")


def _fake_classify(frames):
    for frame in frames:
        if frame.startswith("com.facebook."):
            return dict(FB)
        if frame.startswith("com.appsflyer."):
            return dict(AF)
    return None


def _ctx(event, req_id, t, **fields):
    return RequestContextEvent(event=event, req_id=req_id, timestamp=t, **fields)


def _start(req_id, t, url=URL, frames=FB_FRAMES, method="GET", **fields):
    return _ctx("start", req_id, t, url=url, method=method, frames=list(frames),
                stack_kind="cronet", **fields)


def _store(*events):
    store = RequestContextStore(_fake_classify)
    for event in events:
        store.ingest(event, event.timestamp)
    return store


# --- normalize_request_key ---------------------------------------------------

def test_normalize_lowercases_scheme_host_and_drops_default_port_and_fragment():
    assert normalize_request_key("HTTPS://Example.COM:443/a/B?q=1#frag", "get") == (
        "GET", "https://example.com/a/B?q=1")
    assert normalize_request_key("http://example.com:80/", "POST") == (
        "POST", "http://example.com/")
    assert normalize_request_key("https://example.com:8443/x")[1] == (
        "https://example.com:8443/x")


def test_normalize_canonicalizes_percent_escapes():
    # unreserved escapes decoded, others upper-cased, raw unsafe chars escaped
    assert normalize_request_key("https://h/%7euser/a%2fb?q=%41%3d c")[1] == (
        "https://h/~user/a%2Fb?q=A%3D%20c")
    assert normalize_request_key("https://h/café")[1] == "https://h/caf%C3%A9"


def test_normalize_defaults_method_and_empty_path():
    assert normalize_request_key("https://example.com", "") == ("GET", "https://example.com/")
    assert normalize_request_key("https://user:pw@[2001:DB8::1]:443/p")[1] == (
        "https://[2001:db8::1]/p")


def test_normalize_rejects_non_http_relative_or_broken():
    for url in ("ftp://h/x", "/relative", "", None, "https://", "https://h:99999/",
                "data:text/plain,x"):
        assert normalize_request_key(url) is None
    assert normalize_request_key("https://h/", "G E T") is None


def test_both_sides_agree_after_absolute_request_url():
    flow_side = normalize_request_key(absolute_request_url("/api?x=1", "EXAMPLE.com"), "get")
    assert flow_side == normalize_request_key(URL, "GET") == KEY
    assert absolute_request_url("*", "h") == "" and absolute_request_url("/x", "") == ""
    assert absolute_request_url("http://h/x", "other") == "http://h/x"


def test_collector_classifies_request_frames_past_framework_noise():
    """No prefilter: the real classifier skips framework/transport frames."""
    collector = FlowCollector()
    frames = ["android.os.Handler.dispatch", "java.lang.Thread.run",
              "org.chromium.net.impl.CronetUrlRequest.start", "com.android.x.Y.z",
              "kotlin.coroutines.X.y", "com.facebook.GraphRequest.execute"]
    assert collector._classify_request_frames(frames)["sdk"] == "Facebook SDK"
    assert collector._classify_request_frames(frames[:5]) is None
    assert collector._classify_request_frames([None, "", 3]) is None


def test_java_frame_classification_is_memoised_and_cleared_with_the_resolver(monkeypatch):
    from friTap.analysis.attribution import sdk as sdk_module
    sdk_module.reset_default_resolver()
    resolver = sdk_module._resolver()
    calls = []
    real = resolver.classify_frames

    def counting(java_frames=(), native_modules=()):
        calls.append(tuple(java_frames))
        return real(java_frames, native_modules)

    monkeypatch.setattr(resolver, "classify_frames", counting)
    collector = FlowCollector()
    first = collector._classify_request_frames(FB_FRAMES)
    first["sdk"] = "mutated"  # callers get a copy, never the cached dict
    assert collector._classify_request_frames(FB_FRAMES)["sdk"] == "Facebook SDK"
    assert FlowCollector()._classify_request_frames(FB_FRAMES)["sdk"] == "Facebook SDK"
    assert len(calls) == 1
    assert collector._classify_request_frames(["", 7]) is None
    sdk_module.reset_default_resolver()
    assert sdk_module._cached_java_frames.cache_info().currsize == 0
    sdk_module.reset_default_resolver()


# --- store: match tiers --------------------------------------------------------

def test_single_exact_match_is_java_request_high_and_consumed():
    store = _store(_start("r1", 100.0))
    match = store.match(KEY, 100.3, "f1")
    assert match.claim == {"originator": FB, "source": "java-request", "confidence": "high"}
    assert match.context.matched_flow_ids == ["f1"]
    assert store.match(KEY, 100.4, "f2") is None  # one context <-> one flow


def test_two_sdks_same_url_pick_by_ordinal_with_medium():
    store = _store(_start("fb", 100.0), _start("af", 100.5, frames=AF_FRAMES))
    first = store.match(KEY, 101.0, "f1")
    assert first.context.req_id == "fb"
    assert (first.claim["source"], first.claim["confidence"]) == ("java-request", "medium")
    second = store.match(KEY, 101.2, "f2")
    assert second.context.req_id == "af" and second.claim["originator"] == AF
    assert second.claim["confidence"] == "high"  # the only candidate left


def test_same_sdk_duplicates_stay_high():
    store = _store(_start("a", 100.0), _start("b", 100.1))
    match = store.match(KEY, 100.5, "f1")
    assert match.context.req_id == "a" and match.claim["confidence"] == "high"


def test_time_window_and_slack():
    store = _store(_start("r1", 100.0))
    assert store.match(KEY, 100.0 - join.MATCH_SLACK_SECONDS - 0.1, "early") is None
    assert store.match(KEY, 100.0 + join.MATCH_WINDOW_SECONDS + 1, "late") is None
    assert store.match(KEY, 99.0, "within-slack").context.req_id == "r1"


def test_host_and_time_only_is_no_claim():
    store = _store(_start("r1", 100.0))
    assert store.match(("GET", "https://example.com/other"), 100.1, "f1") is None
    assert store.match(("POST", KEY[1]), 100.1, "f1") is None


def test_unclassified_context_matches_without_claim():
    store = _store(_start("r1", 100.0, frames=["java.lang.Thread.run"]))
    match = store.match(KEY, 100.1, "f1")
    assert match.claim is None and match.context.matched_flow_ids == ["f1"]


def test_redirect_chain_hops_match_their_own_flows():
    hop = "https://cdn.example.com/final"
    store = _store(_start("r1", 100.0, method="POST"),
                   _ctx("redirect", "r1", 100.4, url=hop, status=302))
    first = store.match(("POST", KEY[1]), 100.2, "f1")
    second = store.match(("GET", hop), 100.6, "f2")  # POST -> GET after 302
    assert first.context is second.context
    assert second.context.matched_flow_ids == ["f1", "f2"]
    assert second.claim["source"] == "java-request"
    assert second.context.redirects == [hop]


def test_webview_subresource_is_context_medium_via_owner():
    page = "https://site.example/"
    store = _store(
        _ctx("webview_load", "load", 100.0, url=page, method="GET", frames=list(FB_FRAMES), webview_id="w1"),
        _ctx("webview_request", "sub", 100.5, url="https://cdn.example/app.js",
             webview_id="w1", main_frame=False, frames=["android.webkit.X.y"]))
    match = store.match(("GET", "https://cdn.example/app.js"), 100.6, "f1")
    assert match.claim == {"originator": FB, "source": "context", "confidence": "medium"}


def test_webview_subresource_without_owner_is_no_claim():
    store = _store(_ctx("webview_request", "sub", 100.0, url=URL, webview_id="w9",
                        main_frame=False))
    match = store.match(KEY, 100.1, "f1")
    assert match is not None and match.claim is None


def test_webview_main_frame_is_java_request_high_and_not_double_counted():
    page = "https://site.example/"
    store = _store(
        _ctx("webview_load", "load", 100.0, url=page, method="GET", frames=list(FB_FRAMES), webview_id="w1"),
        _ctx("webview_request", "main", 100.2, url=page, webview_id="w1", main_frame=True))
    match = store.match(("GET", page), 100.3, "f1")
    assert match.context.req_id == "load"
    assert (match.claim["source"], match.claim["confidence"]) == ("java-request", "high")
    assert store.match(("GET", page), 100.4, "f2") is None


def test_load_data_with_base_url_registers_the_owner_but_no_request_key():
    base = "https://site.example/"
    store = _store(
        _ctx("webview_load", "load", 100.0, url=base, frames=list(FB_FRAMES), webview_id="w1"),
        _ctx("webview_request", "sub", 100.5, url="https://cdn.example/app.js",
             webview_id="w1", main_frame=False))
    # a later unrelated GET of the base URL must not borrow the load's stack
    assert store.match(("GET", base), 100.6, "f1") is None
    match = store.match(("GET", "https://cdn.example/app.js"), 100.7, "f2")
    assert match.claim == {"originator": FB, "source": "context", "confidence": "medium"}


# --- store: lifetime -----------------------------------------------------------

def test_ttl_expiry_after_end_and_when_idle():
    store = _store(_start("ended", 100.0), _ctx("end", "ended", 101.0, status=200),
                   _start("idle", 100.0))
    assert store.expire(101.0 + join.ENDED_CONTEXT_TTL - 1) == []
    expired = store.expire(101.0 + join.ENDED_CONTEXT_TTL + 1)
    assert [c.req_id for c in expired] == ["ended"]
    assert [c.req_id for c in store.expire(100.0 + join.IDLE_CONTEXT_TTL + 1)] == ["idle"]
    assert len(store) == 0 and store.match(KEY, 100.1, "f") is None


def test_bound_evicts_least_recently_seen():
    store = RequestContextStore(_fake_classify, max_contexts=2)
    store.ingest(_start("a", 1.0), 1.0)
    store.ingest(_start("b", 2.0), 2.0)
    _, finished = store.ingest(_start("c", 3.0), 3.0)
    assert [c.req_id for c in finished] == ["a"] and len(store) == 2
    assert store.match(KEY, 3.0, "f").context.req_id == "b"


def test_cache_bucket_record_when_cached_and_unmatched():
    store = _store(_start("r1", 100.0),
                   _ctx("response", "r1", 100.1, status=200, cached=True,
                        negotiated_protocol="h2"),
                   _ctx("end", "r1", 100.2))
    record = store.drain()[0].to_record()
    assert record["bucket"] == "cache" and record["cached"] is True
    assert record["protocol"] == "h2" and record["status"] == 200
    assert record["originator"] == FB and "confidence" not in record


# --- collector integration -----------------------------------------------------

def _request_event(t, path="/api?x=1", host="example.com", src_port=51000, data=None):
    return DatalogEvent(
        data=data or f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode(),
        function="SSL_write", direction="write",
        src_addr="10.0.0.2", src_port=src_port, dst_addr="93.184.216.34", dst_port=443,
        ssl_session_id="", timestamp=t)


def _response_event(t, src_port=51000):
    return DatalogEvent(
        data=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        function="SSL_read", direction="read",
        src_addr="93.184.216.34", src_port=443, dst_addr="10.0.0.2", dst_port=src_port,
        ssl_session_id="", timestamp=t)


def _real_start(req_id, t, frames, url=URL):
    return _ctx("start", req_id, t, url=url, method="GET", frames=list(frames),
                stack_kind="cronet")


def _only_flow(collector):
    flows = collector.get_flows()
    assert len(flows) == 1
    return flows[0]


def test_collector_context_before_flow_gives_java_request_high():
    collector = FlowCollector()
    collector.on_request_context(_real_start("r1", 100.0, FB_FRAMES))
    collector.on_data(_request_event(100.2))
    attribution = _only_flow(collector).attribution
    assert attribution["originator"]["sdk"] == "Facebook SDK"
    assert (attribution["source"], attribution["confidence"]) == ("java-request", "high")


def test_collector_late_context_still_matches_and_notifies():
    collector = FlowCollector()
    updates = []
    collector.subscribe(lambda flow, event_type: updates.append(event_type))
    collector.on_data(_request_event(100.0))
    assert "originator" not in (_only_flow(collector).attribution or {})
    collector.on_request_context(_real_start("r1", 100.8, FB_FRAMES))
    assert _only_flow(collector).attribution["source"] == "java-request"
    assert updates[-1] == "updated"


def test_collector_host_only_context_makes_no_claim():
    collector = FlowCollector()
    collector.on_request_context(_real_start("r1", 100.0, FB_FRAMES,
                                             url="https://example.com/elsewhere"))
    collector.on_data(_request_event(100.1))
    assert "originator" not in (_only_flow(collector).attribution or {})


def test_collector_java_request_replaces_fallback_claim():
    collector = FlowCollector()
    collector.on_data(_request_event(100.0))
    flow = collector._flows[_only_flow(collector).flow_id]  # the live flow, not a copy
    flow.attribution = {**(flow.attribution or {}), "originator": dict(AF),
                        "source": "connection-fallback", "confidence": "low"}
    collector.on_request_context(_real_start("r1", 100.1, FB_FRAMES))
    assert flow.attribution["originator"]["sdk"] == "Facebook SDK"
    assert flow.attribution["confidence"] == "high"


def test_collector_two_sdks_on_one_connection_mark_mixed():
    collector = FlowCollector()
    collector.on_request_context(_real_start("fb", 100.0, FB_FRAMES))
    collector.on_request_context(_real_start("af", 100.0, AF_FRAMES,
                                             url="https://example.com/track"))
    collector.on_data(_request_event(100.1))
    collector.on_data(_response_event(100.2))
    collector.on_data(_request_event(100.3, path="/track"))
    flows = sorted(collector.get_flows(), key=lambda f: f.flow_id)
    assert [f.attribution["originator"]["sdk"] for f in flows] == ["Facebook SDK", "AppsFlyer"]
    assert all(f.attribution.get("mixed") is True for f in flows)
    record = collector._connection_attributions[flows[0].connection_id]
    assert record.mixed and record.sdk is None and record.caller_stack is None
    assert record.sdk_names == {"Facebook SDK", "AppsFlyer"}


def test_collector_writes_tap_records_with_matched_flow_ids(tmp_path):
    path = str(tmp_path / "ctx.tap")
    writer = TapWriter()
    writer.open(path, target="test")
    collector = FlowCollector()
    collector.set_request_context_sink(writer.write_request_context)
    collector.on_request_context(_real_start("matched", 100.0, FB_FRAMES))
    collector.on_request_context(_real_start("cached", 100.0, AF_FRAMES,
                                             url="https://example.com/cached"))
    collector.on_request_context(_ctx("response", "cached", 100.1, cached=True, status=200))
    collector.on_data(_request_event(100.2))
    flow_id = _only_flow(collector).flow_id
    collector.flush()  # drains the live contexts to the sink
    assert len(collector._request_contexts) == 0
    writer.close()
    with TapReader(path) as reader:
        records = {r["req_id"]: r for r in reader.iter_request_contexts()}
    assert records["matched"]["matched_flow_ids"] == [flow_id]
    assert records["matched"]["source"] == "java-request"
    assert records["matched"]["confidence"] == "high"
    assert records["cached"]["bucket"] == "cache"
    assert records["cached"].get("matched_flow_ids") == []


def test_collector_clear_flushes_live_contexts_to_the_sink():
    collector = FlowCollector()
    seen = []
    collector.set_request_context_sink(seen.append)
    collector.on_request_context(_real_start("r1", 100.0, FB_FRAMES))
    collector.clear()
    assert [record["req_id"] for record in seen] == ["r1"]
    assert len(collector._request_contexts) == 0


def test_collector_expires_ended_contexts_to_the_sink(monkeypatch):
    """Expiry runs in the periodic sweep (not per RequestContextEvent)."""
    monkeypatch.setattr(collector_module, "_SWEEP_INTERVAL", 1)
    collector = FlowCollector()
    collector.use_event_clock(True)
    seen = []
    collector.set_request_context_sink(seen.append)
    collector.on_request_context(_real_start("r1", 100.0, FB_FRAMES))
    collector.on_request_context(_ctx("end", "r1", 101.0))
    late = 101.0 + join.ENDED_CONTEXT_TTL + 1
    collector.on_request_context(_real_start("r2", late, FB_FRAMES))
    assert seen == []  # no per-event expiry
    collector.on_data(_request_event(late, path="/other"))
    assert [record["req_id"] for record in seen] == ["r1"]
    assert len(collector._request_contexts) == 1


def test_collector_join_is_lazy_until_the_first_context():
    collector = FlowCollector()
    collector.on_data(_request_event(100.0))
    flow = _only_flow(collector)
    assert not collector._request_join_enabled
    assert collector._request_join_flows == {} and not collector._request_join_attempted
    # the first context backfills the live flows, so the earlier flow matches
    collector.on_request_context(_real_start("r1", 99.9, FB_FRAMES))
    assert collector._request_join_enabled
    assert flow.flow_id in collector._request_join_attempted
    flow = _only_flow(collector)
    assert flow.attribution["originator"]["sdk"] == "Facebook SDK"
    assert flow.attribution["source"] == "java-request"


def test_collector_marks_a_final_unkeyable_request_attempted():
    collector = FlowCollector()
    collector.on_request_context(_real_start("r1", 100.0, FB_FRAMES))
    collector.on_data(_request_event(100.1, data=b"HELLO not http\r\n\r\n"))
    flow = _only_flow(collector)
    assert collector._flow_request_key(flow) is None
    collector.flush()  # completes the flow: its request is final
    assert flow.flow_id in collector._request_join_attempted


def test_collector_waiting_index_is_bounded_per_key_and_by_keys(monkeypatch):
    monkeypatch.setattr(collector_module, "MAX_REQUEST_JOIN_KEYS", 2)
    monkeypatch.setattr(collector_module, "MAX_REQUEST_JOIN_FLOWS_PER_KEY", 2)
    collector = FlowCollector()
    for i in range(3):
        collector._wait_for_request_context(("GET", "https://a/"), _flow_stub(f"a{i}"))
    assert [fid for _, fid in collector._request_join_flows[("GET", "https://a/")]] == [
        "a1", "a2"]
    collector._wait_for_request_context(("GET", "https://b/"), _flow_stub("b"))
    collector._wait_for_request_context(("GET", "https://c/"), _flow_stub("c"))
    assert list(collector._request_join_flows) == [("GET", "https://b/"), ("GET", "https://c/")]


def _flow_stub(flow_id):
    from types import SimpleNamespace
    return SimpleNamespace(flow_id=flow_id, started=100.0)


def test_request_originator_record_keeps_first_caller_stack_direct():
    from friTap.events import CallerStackEvent
    collector = FlowCollector()
    collector.on_request_context(_real_start("r1", 100.0, AF_FRAMES))
    collector.on_data(_request_event(100.1))
    flow = _only_flow(collector)
    record = collector._connection_attributions[flow.connection_id]
    assert record.caller_stack is None and record.sdk_names == {"AppsFlyer"}
    collector.on_sdk(CallerStackEvent(
        ssl_session_id="0", src_addr="10.0.0.2", src_port=51000,
        dst_addr="93.184.216.34", dst_port=443, sdk=dict(FB)))
    live = collector._flows[flow.flow_id]
    # the stack still counts as the connection's first (direct) join ...
    assert record.caller_stack is not None and record.sdk["sdk"] == "Facebook SDK"
    # ... but the weaker native-stack/medium claim never replaces java-request/high,
    # and the differing originators mark the connection mixed
    assert live.attribution["source"] == "java-request"
    assert live.attribution["originator"]["sdk"] == "AppsFlyer"
    assert record.mixed and live.attribution.get("mixed") is True


def test_tap_output_handler_persists_request_contexts_on_close(tmp_path):
    from friTap.events import EventBus
    from friTap.output.tap_handler import TapOutputHandler
    path = str(tmp_path / "handler.tap")
    bus = EventBus()
    handler = TapOutputHandler(path, target="t")
    handler.setup(bus)
    bus.emit(_real_start("live", 100.0, FB_FRAMES))
    handler.close()
    with TapReader(path) as reader:
        assert [r["req_id"] for r in reader.iter_request_contexts()] == ["live"]


# --- key symmetry, WebView owner, claim strength, join marks ---

def test_long_url_context_capped_by_the_router_matches_the_full_flow_url():
    from friTap.caller_stack_shapes import REQUEST_CONTEXT_URL_LIMIT, capped_text
    full = "https://example.com/api?" + "&".join(f"k{i}=v%27{i}" for i in range(400))
    assert len(full) > 3000
    capped = capped_text(full, REQUEST_CONTEXT_URL_LIMIT)  # what the router keeps
    assert capped != full
    store = _store(_start("long", 100.0, url=capped))
    flow_key = normalize_request_key(full, "GET")
    match = store.match(flow_key, 100.1, "f1")
    assert match is not None and match.context.req_id == "long"
    assert len(flow_key[1]) == join.REQUEST_KEY_URL_LIMIT


def test_router_cut_url_of_unreserved_escapes_still_matches_the_full_flow_url():
    from friTap.caller_stack_shapes import REQUEST_CONTEXT_URL_LIMIT, capped_text
    full = "https://example.com/p?" + "%41" * 1000  # each escape decodes to one char
    capped = capped_text(full, REQUEST_CONTEXT_URL_LIMIT)
    assert len(normalize_request_key(capped)[1]) < 1024
    store = _store(_start("long", 100.0, url=capped))
    match = store.match(normalize_request_key(full, "GET"), 100.1, "f1")
    assert match is not None and match.context.req_id == "long"


def test_key_limit_is_a_third_of_the_router_url_cut():
    from friTap.caller_stack_shapes import REQUEST_CONTEXT_URL_LIMIT
    assert join.REQUEST_KEY_URL_LIMIT == REQUEST_CONTEXT_URL_LIMIT // 3


def test_key_cap_is_symmetric_when_the_raw_cut_splits_an_escape():
    full = "https://example.com/p?" + "a%2F" * 1000
    for cut in (2046, 2047, 2048):  # inside / right after an escape
        assert normalize_request_key(full[:cut]) == normalize_request_key(full)


def test_webview_owner_kept_alive_by_its_subresources():
    page = "https://site.example/"
    store = _store(_ctx("webview_load", "load", 100.0, url=page, method="GET", frames=list(FB_FRAMES),
                        webview_id="w1"))
    step = join.IDLE_CONTEXT_TTL / 2
    t = 100.0
    for i in range(4):  # subresources keep arriving well past the idle TTL
        t += step
        store.ingest(_ctx("webview_request", f"sub{i}", t, url=f"https://cdn.example/{i}.js",
                          webview_id="w1", main_frame=False), t)
        assert "load" not in [c.req_id for c in store.expire(t)]
    assert t - 100.0 > join.IDLE_CONTEXT_TTL
    late = t + 1
    store.ingest(_ctx("webview_request", "late", late, url="https://cdn.example/late.js",
                      webview_id="w1", main_frame=False), late)
    assert store._contexts["late"].owner_id == "load"
    match = store.match(("GET", "https://cdn.example/late.js"), late + 0.1, "f1")
    assert match.claim == {"originator": FB, "source": "context", "confidence": "medium"}


def test_main_frame_webview_request_to_another_url_is_context_medium():
    page = "https://site.example/"
    other = "https://site.example/next"
    store = _store(
        _ctx("webview_load", "load", 100.0, url=page, method="GET", frames=list(FB_FRAMES), webview_id="w1"),
        _ctx("webview_request", "nav", 100.2, url=other, webview_id="w1", main_frame=True))
    match = store.match(("GET", other), 100.3, "f1")
    assert match.context.req_id == "nav"
    assert match.claim == {"originator": FB, "source": "context", "confidence": "medium"}


def test_main_frame_webview_request_of_the_owner_url_stays_java_request_high():
    page = "https://site.example/"
    store = _store(
        _ctx("webview_load", "load", 100.0, url=page, method="GET", frames=list(FB_FRAMES), webview_id="w1"))
    # a main-frame webview_request of the loaded URL is the loadUrl navigation
    # itself (normally matched via the load context, which it is not indexed beside)
    nav = join.RequestContext(req_id="nav", kind="webview_request", url=page,
                              main_frame=True, owner_id="load", originator=dict(FB))
    claim = store._claim_for(nav, [nav], normalize_request_key(page)[1])
    assert (claim["source"], claim["confidence"]) == ("java-request", "high")
    # the same request to another URL inherits the owner's originator: context only
    other = normalize_request_key(page + "next")[1]
    claim = store._claim_for(nav, [nav], other)
    assert (claim["source"], claim["confidence"]) == ("context", "medium")


SPECIAL_CHARS = {"'": "%27", '"': "%22", "<": "%3C", ">": "%3E", "`": "%60", " ": "%20"}


def test_raw_and_escaped_special_chars_canonicalize_alike_in_path_and_query():
    for raw, escaped in SPECIAL_CHARS.items():
        for template in ("https://h/a{c}b?q=1", "https://h/p?q={c}x{c}y"):
            raw_key = normalize_request_key(template.format(c=raw))
            assert raw_key == normalize_request_key(template.format(c=escaped)), raw
            assert raw_key == normalize_request_key(template.format(c=escaped.lower()))
            assert escaped in raw_key[1]


def test_structural_delimiters_are_never_decoded():
    assert normalize_request_key("https://h/a%2Fb?x=%26y%3D1")[1] == (
        "https://h/a%2Fb?x=%26y%3D1")
    assert normalize_request_key("https://h/a/b?x=&y=1")[1] == "https://h/a/b?x=&y=1"


def test_join_mark_outlives_many_flows_so_an_old_flow_never_steals_a_newer_context():
    from types import SimpleNamespace

    from friTap.flow.collector import _PendingEvents
    from friTap.flow.models import Flow
    collector = FlowCollector()

    def flow(flow_id, path, started):
        result = Flow(flow_id=flow_id, started=started)
        result.request = SimpleNamespace(method="GET", url=path, host="example.com",
                                         is_request=True, is_complete=True)
        return result

    old = flow("old", "/target", 100.0)
    collector._try_request_join(old, _PendingEvents([]))  # no context yet: waits
    fillers = [flow(f"f{i}", f"/filler/{i}", 100.0) for i in range(8192 + 10)]
    for filler in fillers:  # more flows than any fixed-size bound would hold
        collector._try_request_join(filler, _PendingEvents([]))
    collector._request_contexts.ingest(_real_start("newer", 101.0, FB_FRAMES,
                                                   url="https://example.com/target"), 101.0)
    collector._try_request_join(old, _PendingEvents([]))  # the old flow is touched again
    assert old.attribution is None or not old.attribution.get("originator")
    newer = flow("new", "/target", 101.1)
    collector._try_request_join(newer, _PendingEvents([]))
    assert newer.attribution["originator"]["sdk"] == "Facebook SDK"


# --- publication, index and retention ------------------------------------------

def test_pending_events_queue_each_flow_once():
    from friTap.flow.collector import _PendingEvents
    from friTap.flow.models import Flow
    first, second = Flow(flow_id="a"), Flow(flow_id="b")
    updates = _PendingEvents([("created", first)])
    updates.add_updated(first)
    updates.add_updated(second)
    updates.add_updated(second)
    assert updates.events == [("created", first), ("updated", second)]
    assert updates.flows() == [first, second]


def test_publish_notifies_flows_before_request_records_and_survives_a_failing_sink():
    collector = FlowCollector()
    order = []
    collector.subscribe(lambda flow, event_type: order.append(event_type))

    def failing_sink(record):
        order.append(record["req_id"])
        raise RuntimeError("sink broke")

    collector.set_request_context_sink(failing_sink)
    collector.on_data(_request_event(100.0))
    collector.on_request_context(_real_start("r1", 100.1, FB_FRAMES))
    order.clear()
    collector.flush()
    assert order[-1] == "r1"
    assert "completed" in order[:-1]


def test_consumed_context_leaves_the_index_for_that_url():
    store = _store(_start("r1", 100.0))
    assert store.match(KEY, 100.2, "f1") is not None
    assert KEY not in store._index
    assert store.match(KEY, 100.3, "f2") is None
    # re-learning the consumed URL indexes nothing new
    assert store.ingest(_start("r1", 100.4), 100.4) == ([], [])


def test_redirect_hop_is_indexed_under_its_method_and_get():
    store = _store(_start("r1", 100.0, method="POST"),
                   _ctx("redirect", "r1", 100.1, url="https://example.com/next"))
    assert ("POST", "https://example.com/next") in store._index
    assert ("GET", "https://example.com/next") in store._index


def test_waiting_flow_older_than_the_slack_is_dropped_on_retry():
    collector = FlowCollector()
    collector.on_request_context(_real_start("other", 90.0, AF_FRAMES,
                                             url="https://example.com/unrelated"))
    collector.on_data(_request_event(100.0))
    key = ("GET", "https://example.com/api?x=1")
    assert key in collector._request_join_flows
    collector.on_request_context(_real_start("r1", 100.0 + join.MATCH_SLACK_SECONDS + 1, FB_FRAMES))
    assert key not in collector._request_join_flows
    assert "originator" not in (_only_flow(collector).attribution or {})


def test_enabling_the_join_skips_flows_too_old_to_match():
    collector = FlowCollector()
    collector.on_data(_request_event(100.0))
    collector.on_request_context(_real_start("r1", 110.0, FB_FRAMES,
                                             url="https://example.com/elsewhere"))
    assert _only_flow(collector).flow_id in collector._request_join_attempted
    assert collector._request_join_flows == {}


def test_flow_host_falls_back_to_the_quic_sni():
    from friTap.flow.models import Flow
    flow = Flow(flow_id="q", transport="quic")
    flow.quic.sni = "quic.example.com"
    assert FlowCollector()._flow_host(flow) == "quic.example.com"


def test_chromium_bucket_check_is_skipped_until_a_chromium_transport_is_seen():
    collector = FlowCollector()
    collector.on_data(_request_event(100.0))
    assert collector._chromium_transport_seen is False
