"""QUIC connections join on client_random like TCP TLS ones.

A QuicConnection's records are keyed ``sid:quic:0x<ptr>[#gen]``; once the
agent has bound the connection's TLS handshake they also carry the
client_random. The two keys must name one connection whichever arrives
first, its HTTP/3 stream flows carry the client_random, and caller stacks /
request contexts attribute those flows as they do TCP flows.
"""

import time

from friTap.connection_index import DUMMY_SESSION_ID_BASE, connection_scoped_session_key
from friTap.events import (
    SESSION_STARTED,
    CallerStackEvent,
    DatalogEvent,
    EventBus,
    SessionEvent,
)
from friTap.flow.collector import FlowCollector
from friTap.flow.layers import QuicLayer
from friTap.message_router import MessageRouter
from tests.unit.test_collector_quiche_frame_streams import _chrome_like_session
from tests.unit.test_quic_protocol_tag_flow import (
    QUIC_CONNECTION,
    _datalog_payload,
    _lifecycle_payload,
    _request_flows,
)
from tests.unit.test_request_context_join import FB_FRAMES, _real_start

CLIENT_RANDOM = "c3" * 32
OTHER_RANDOM = "d4" * 32
CR_KEY = f"cr:quic:{CLIENT_RANDOM}"
SID_KEY = f"sid:quic:{QUIC_CONNECTION}"
FB_SDK = {"sdk": "Facebook SDK", "vendor": "Meta", "category": "social"}
AF_SDK = {"sdk": "AppsFlyer", "vendor": "AppsFlyer", "category": "attribution"}
SESSION_LENGTH = len(_chrome_like_session())


def _wire_up():
    bus = EventBus()
    collector = FlowCollector(event_bus=bus)
    for event_type, handler in ((DatalogEvent, collector.on_data),
                                (SessionEvent, collector.on_session_event),
                                (CallerStackEvent, collector.on_sdk)):
        bus.subscribe(event_type, handler)
    return collector, MessageRouter(bus, active_protocol=["tls"])


NO_ENDPOINTS = {"src_addr": "", "src_port": 0, "dst_addr": "", "dst_port": 0}


def _route_session(router, client_random=CLIENT_RANDOM, cr_from=0,
                   session_id=QUIC_CONNECTION, time_offset=0.0, endpoints=None):
    """Route one Chrome-like HTTP/3 session; records from index *cr_from* on
    carry *client_random*."""
    for index, event in enumerate(_chrome_like_session()):
        payload = {**_datalog_payload(event), "ssl_session_id": session_id,
                   **(endpoints or {})}
        if index >= cr_from:
            payload["client_random"] = client_random
        event.timestamp += time_offset
        router.route(payload, event.data)


def _cr_stack(sdk, client_random=CLIENT_RANDOM):
    return CallerStackEvent(ssl_session_id="0", client_random=client_random, sdk=dict(sdk))


def _connection_ids(collector) -> set:
    return {flow.connection_id for flow in collector.get_flows()}


def test_records_carrying_client_random_key_the_connection_by_it():
    collector, router = _wire_up()
    _route_session(router)
    flows = _request_flows(collector)
    assert {f.request.method for f in flows} == {"GET", "POST"}
    assert _connection_ids(collector) == {f"cr:quic:{CLIENT_RANDOM}"}
    assert all(f.quic.client_random == CLIENT_RANDOM for f in flows)
    assert all(f.layer("tls") is None for f in flows)


def test_client_random_after_the_first_chunk_promotes_the_connection_to_it():
    collector, router = _wire_up()
    _route_session(router, cr_from=3)
    flows = _request_flows(collector)
    assert {f.request.method for f in flows} == {"GET", "POST"}
    assert _connection_ids(collector) == {CR_KEY}
    assert all(f.quic.client_random == CLIENT_RANDOM for f in collector.get_flows())
    get = next(f for f in flows if f.request.method == "GET")
    assert get.response is not None and get.response.status_code == 200


def test_late_client_random_without_endpoints_keeps_one_connection():
    collector, router = _wire_up()
    _route_session(router, cr_from=3, endpoints=NO_ENDPOINTS)
    assert {f.request.method for f in _request_flows(collector)} == {"GET", "POST"}
    assert _connection_ids(collector) == {CR_KEY}
    assert all(f.quic.client_random == CLIENT_RANDOM for f in collector.get_flows())


def test_client_random_only_on_the_last_record_backfills_earlier_streams():
    collector, router = _wire_up()
    _route_session(router, cr_from=SESSION_LENGTH - 1)
    assert _connection_ids(collector) == {CR_KEY}
    assert all(f.quic.client_random == CLIENT_RANDOM for f in collector.get_flows())


def test_lifecycle_without_client_random_finds_the_connection_by_sid():
    collector, router = _wire_up()
    seen = []
    collector._event_bus.subscribe(SessionEvent, seen.append)
    _route_session(router)
    conn_id = f"cr:quic:{CLIENT_RANDOM}"
    assert collector._key_aliases.lookup(
        f"sid:quic:{QUIC_CONNECTION}", "", 0, "", 0, collector._connections.__contains__,
    ) == conn_id
    router.route({**_lifecycle_payload("destroyed"), "src_addr": "", "dst_addr": "",
                  "src_port": 0, "dst_port": 0}, b"")
    assert conn_id not in collector._connections


def test_client_random_is_case_insensitive():
    collector, router = _wire_up()
    _route_session(router, client_random=CLIENT_RANDOM.upper(), cr_from=2)
    collector.on_sdk(_cr_stack(FB_SDK, client_random=CLIENT_RANDOM))
    flows = collector.get_flows()
    assert _connection_ids(collector) == {CR_KEY}
    assert all(f.quic.client_random == CLIENT_RANDOM for f in flows)
    assert all(f.sdk == FB_SDK for f in flows)


def test_new_generation_with_another_client_random_is_a_new_connection():
    collector, router = _wire_up()
    _route_session(router)
    _route_session(router, client_random=OTHER_RANDOM, cr_from=1,
                   session_id=f"{QUIC_CONNECTION}#2", time_offset=1.0)
    assert _connection_ids(collector) == {
        f"cr:quic:{CLIENT_RANDOM}", f"cr:quic:{OTHER_RANDOM}"}
    by_conn = {}
    for flow in _request_flows(collector):
        by_conn.setdefault(flow.connection_id, set()).add(flow.quic.client_random)
    assert by_conn == {f"cr:quic:{CLIENT_RANDOM}": {CLIENT_RANDOM},
                       f"cr:quic:{OTHER_RANDOM}": {OTHER_RANDOM}}


def test_caller_stack_before_the_data_drains_onto_every_stream():
    collector, router = _wire_up()
    collector.on_sdk(_cr_stack(FB_SDK))
    _route_session(router, cr_from=4)
    flows = _request_flows(collector)
    assert flows and all(f.sdk == FB_SDK for f in flows)


def test_request_context_attributes_a_quic_stream_flow():
    collector, router = _wire_up()
    # Routed records are stamped with the host clock, so the context is too.
    collector.on_request_context(_real_start("r1", time.time(), FB_FRAMES,
                                             url="https://www.google.com/"))
    _route_session(router, cr_from=2)
    get = next(f for f in _request_flows(collector) if f.request.method == "GET")
    assert get.quic.client_random == CLIENT_RANDOM
    assert get.attribution["originator"]["sdk"] == "Facebook SDK"
    assert get.attribution["source"] == "java-request"


def test_two_sdks_on_one_quic_connection_mark_every_stream_mixed():
    collector, router = _wire_up()
    _route_session(router, cr_from=2)
    collector.on_sdk(_cr_stack(FB_SDK))
    collector.on_sdk(_cr_stack(AF_SDK))
    conn_id = CR_KEY
    assert collector._connection_attributions[conn_id].mixed
    flows = _request_flows(collector)
    assert flows and all(f.attribution.get("mixed") is True for f in flows)
    assert all(f.sdk == FB_SDK for f in flows)


def test_only_quic_session_ids_name_a_single_connection():
    assert connection_scoped_session_key(QUIC_CONNECTION, "quic") == f"sid:quic:{QUIC_CONNECTION}"
    assert connection_scoped_session_key(QUIC_CONNECTION, "tls") == ""
    assert connection_scoped_session_key("", "quic") == ""
    assert connection_scoped_session_key(DUMMY_SESSION_ID_BASE + "0", "quic") == ""


def test_session_key_reuses_a_sid_record_key():
    record_key = f"sid:quic:{QUIC_CONNECTION}"
    assert connection_scoped_session_key(QUIC_CONNECTION, "quic", record_key) is record_key
    # A cr: record key is not the session key, so it is still built from the token.
    assert connection_scoped_session_key(
        QUIC_CONNECTION, "quic", f"cr:quic:{CLIENT_RANDOM}") == record_key
    assert connection_scoped_session_key(QUIC_CONNECTION, "tls", record_key) == ""


def test_session_alias_is_written_only_when_it_changes():
    from friTap.connection_index import ConnectionKeyAliases
    aliases = ConnectionKeyAliases()
    session_key, cr_key = "sid:quic:1", "cr:quic:aa"
    live = {session_key}.__contains__
    assert aliases.resolve(session_key, "", 0, "", 0, "quic", live, session_key=session_key) == session_key
    assert aliases.resolve(cr_key, "", 0, "", 0, "quic", live, session_key=session_key) == session_key
    writes = []
    aliases._remember = lambda *args: writes.append(args)
    assert aliases.resolve(cr_key, "", 0, "", 0, "quic", live, session_key=session_key) == session_key
    assert writes == []


def test_quic_layer_round_trips_client_random_only_when_set():
    layer = QuicLayer(client_random=CLIENT_RANDOM)
    assert QuicLayer.from_dict(layer.to_dict()).client_random == CLIENT_RANDOM
    assert "client_random" not in QuicLayer(sni="x").to_dict()
    assert QuicLayer().is_empty() and not layer.is_empty()


# Promotion of a sid:quic: connection to its cr:quic: key ------------------- #

def _route_records(router, carries_cr, client_random=CLIENT_RANDOM,
                   session_id=QUIC_CONNECTION, time_offset=0.0, start=0, stop=None):
    """Route the Chrome-like session's records *start*..*stop*; record *i*
    carries *client_random* when ``carries_cr(i)``."""
    for index, event in list(enumerate(_chrome_like_session()))[start:stop]:
        payload = {**_datalog_payload(event), "ssl_session_id": session_id}
        if carries_cr(index):
            payload["client_random"] = client_random
        event.timestamp += time_offset
        router.route(payload, event.data)


def test_promotion_rewrites_the_connection_id_of_existing_flows():
    collector, router = _wire_up()
    updated = []
    collector.subscribe(lambda flow, kind: updated.append((flow.flow_id, kind)))
    _route_records(router, lambda i: False, stop=3)
    early = list(collector._flows.values())
    assert early and {f.connection_id for f in early} == {SID_KEY}
    updated.clear()
    _route_records(router, lambda i: True, start=3)
    assert {f.connection_id for f in early} == {CR_KEY}
    # Flow ids stay stable: subscribers already know the flows by them.
    assert all(f.flow_id.startswith(f"{SID_KEY}:") for f in early)
    renamed = {flow_id for flow_id, kind in updated if kind == "updated"}
    assert {f.flow_id for f in early} <= renamed
    assert collector._conn_by_client_random[CLIENT_RANDOM] == CR_KEY
    assert set(collector._flow_index) == {CR_KEY}


def test_session_metadata_keyed_by_client_random_survives_the_promotion():
    collector, router = _wire_up()
    _route_records(router, lambda i: False, stop=3)
    collector._session_tls[SID_KEY] = {"sni": "old.example", "quic_version": "1"}
    collector.on_session_event(SessionEvent(
        event_type=SESSION_STARTED, connection_id=CR_KEY, client_random=CLIENT_RANDOM,
        server_name="www.example.com", alpn="h3"))
    assert CR_KEY in collector._session_tls
    _route_records(router, lambda i: True, start=3)
    assert collector._session_tls[CR_KEY]["sni"] == "www.example.com"
    assert collector._session_tls[CR_KEY]["quic_version"] == "1"
    flows = collector.get_flows()
    assert flows and all(f.connection_id == CR_KEY for f in flows)
    assert all(f.quic.sni == "www.example.com" and f.quic.alpn == "h3" for f in flows)


def test_rename_merges_tables_the_new_key_already_holds():
    from friTap.flow.collector import _ConnectionAttribution
    collector, router = _wire_up()
    _route_records(router, lambda i: False, stop=3)
    collector._connection_attributions[SID_KEY] = _ConnectionAttribution(
        sdk=dict(FB_SDK), caller_stack={"frames": []}, sdk_names={"Facebook SDK"})
    collector._connection_attributions[CR_KEY] = _ConnectionAttribution(sdk_names={"AppsFlyer"})
    collector._lifetime_first_seq[CR_KEY] = 99
    _route_records(router, lambda i: True, start=3)
    record = collector._connection_attributions[CR_KEY]
    assert record.sdk == FB_SDK and record.caller_stack == {"frames": []}
    assert record.sdk_names == {"Facebook SDK", "AppsFlyer"} and record.mixed
    assert collector._lifetime_first_seq[CR_KEY] == 0
    assert SID_KEY not in collector._connection_attributions


def test_rename_keeps_the_old_lifetime_baseline_of_the_shared_counter():
    collector, router = _wire_up()
    _route_records(router, lambda i: False, stop=3)
    # A later lifetime of the sid key starts at sequence 1; a stale 0 under the
    # never-minting cr key belongs to no counter and must not win via min().
    collector._lifetime_first_seq[SID_KEY] = 1
    collector._lifetime_first_seq[CR_KEY] = 0
    _route_records(router, lambda i: True, start=3)
    assert collector._lifetime_first_seq[CR_KEY] == 1
    assert SID_KEY not in collector._lifetime_first_seq


def test_records_without_client_random_after_the_promotion_join_it():
    collector, router = _wire_up()
    _route_records(router, lambda i: i == 3)
    assert _connection_ids(collector) == {CR_KEY}
    assert {f.request.method for f in _request_flows(collector)} == {"GET", "POST"}
    assert list(collector._connections) == [CR_KEY]


def test_old_session_key_still_resolves_to_the_promoted_connection():
    collector, router = _wire_up()
    _route_session(router, cr_from=3)
    assert collector._key_aliases.canonical(SID_KEY) == CR_KEY
    assert collector._key_aliases.lookup(
        SID_KEY, "", 0, "", 0, collector._connections.__contains__) == CR_KEY
    router.route({**_lifecycle_payload("destroyed"), **NO_ENDPOINTS}, b"")
    assert CR_KEY not in collector._connections


def test_connection_keyed_by_another_client_random_is_not_rekeyed():
    collector, router = _wire_up()
    _route_session(router)
    _route_records(router, lambda i: True, client_random=OTHER_RANDOM, stop=2)
    assert _connection_ids(collector) == {CR_KEY}
    assert list(collector._connections) == [CR_KEY]


def test_new_generation_is_promoted_alone_and_its_lifecycle_finds_it():
    collector, router = _wire_up()
    _route_session(router)
    _route_session(router, client_random=OTHER_RANDOM, cr_from=3,
                   session_id=f"{QUIC_CONNECTION}#2", time_offset=1.0)
    other_key = f"cr:quic:{OTHER_RANDOM}"
    assert _connection_ids(collector) == {CR_KEY, other_key}
    assert collector._key_aliases.canonical(f"{SID_KEY}#2") == other_key
    router.route({**_lifecycle_payload("destroyed"), **NO_ENDPOINTS,
                  "ssl_session_id": f"{QUIC_CONNECTION}#2"}, b"")
    assert other_key not in collector._connections
    assert CR_KEY in collector._connections


def test_promotion_is_idempotent():
    collector, router = _wire_up()
    _route_session(router, cr_from=3)
    _route_records(router, lambda i: True, stop=2, time_offset=0.5)
    assert _connection_ids(collector) == {CR_KEY}
    assert list(collector._connections) == [CR_KEY]
    aliases = collector._key_aliases
    aliases.rename(SID_KEY, CR_KEY)
    assert aliases.canonical(SID_KEY) == CR_KEY and aliases.canonical(CR_KEY) == CR_KEY


def test_tls_session_connection_is_not_promoted():
    from friTap.connection_index import promotes_to_client_random_key
    assert not promotes_to_client_random_key("cr:tls:aa", "sid:tls:bb")
    assert not promotes_to_client_random_key("cr:quic:aa", "cr:quic:bb")
    assert not promotes_to_client_random_key("cr:quic:aa", "net:quic:x")
    assert promotes_to_client_random_key("cr:quic:aa", "sid:quic:0x1")
    collector = FlowCollector()
    tls_sid = "ab" * 32
    endpoints = {"src_addr": "10.0.0.2", "src_port": 40000,
                 "dst_addr": "93.184.216.34", "dst_port": 443}
    for client_random in ("", CLIENT_RANDOM):
        collector.on_data(DatalogEvent(
            data=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            function="SSL_write", direction="write", ssl_session_id=tls_sid,
            client_random=client_random, protocol="tls", **endpoints))
    assert _connection_ids(collector) == {f"sid:tls:{tls_sid}"}


def test_rename_repoints_every_alias_and_endpoint_claim():
    from friTap.connection_index import ConnectionKeyAliases
    aliases = ConnectionKeyAliases()
    old, new = "sid:quic:1", "cr:quic:aa"
    live = {old}.__contains__
    endpoints = ("10.0.0.2", 5000, "8.8.8.8", 443)
    assert aliases.resolve(old, *endpoints, "quic", live) == old
    assert aliases.resolve("net:quic:x", *endpoints, "quic", live) == old
    aliases.resolve(new, "", 0, "", 0, "quic", live, session_key=old)
    aliases.rename(old, new)
    assert aliases.canonical(old) == new
    assert aliases.canonical("net:quic:x") == new
    assert aliases.canonical(new) == new
    assert aliases.resolve("net:quic:y", *endpoints, "quic", {new}.__contains__) == new


def _aliases_with_session_owner(old="sid:quic:1"):
    from friTap.connection_index import ConnectionKeyAliases
    aliases = ConnectionKeyAliases()
    live = {old}
    assert aliases.resolve(old, "", 0, "", 0, "quic", live.__contains__, session_key=old) == old
    return aliases, live


def test_index_promotes_a_live_sid_owner_when_allowed():
    old, new = "sid:quic:1", "cr:quic:aa"
    aliases, live = _aliases_with_session_owner(old)
    calls = []
    allow = lambda owner, key: calls.append((owner, key)) or True  # noqa: E731
    assert aliases.resolve(new, "", 0, "", 0, "quic", live.__contains__,
                           session_key=old, may_promote=allow) == new
    assert aliases.promoted_from == old and calls == [(old, new)]
    assert aliases.canonical(old) == new
    live = {new}
    assert aliases.resolve(new, "", 0, "", 0, "quic", live.__contains__,
                           session_key=old, may_promote=allow) == new
    assert aliases.promoted_from is None and len(calls) == 1


def test_index_folds_instead_of_promoting_when_refused():
    old, new = "sid:quic:1", "cr:quic:aa"
    aliases, live = _aliases_with_session_owner(old)
    assert aliases.resolve(new, "", 0, "", 0, "quic", live.__contains__,
                           session_key=old, may_promote=lambda *_: False) == old
    assert aliases.promoted_from is None and aliases.canonical(new) == old


def test_index_never_consults_the_callback_for_non_quic_keys():
    old = "sid:quic:1"
    aliases, live = _aliases_with_session_owner(old)

    def forbidden(*_):
        raise AssertionError("callback consulted")
    for key in ("cr:tls:aa", "net:quic:x", old):
        aliases.resolve(key, "", 0, "", 0, "quic", live.__contains__,
                        session_key=old, may_promote=forbidden)
    assert aliases.promoted_from is None


def test_session_meta_merge_keeps_set_fields_against_empty_ones():
    from friTap.flow.collector import _merge_session_meta
    target = {"sni": "a.example", "alpn": "h3"}
    merged = _merge_session_meta(target, {"sni": "", "alpn": "h3-29", "cipher": "x"})
    assert merged is target
    assert merged == {"sni": "a.example", "alpn": "h3-29", "cipher": "x"}


def test_attribution_adopts_only_missing_stack_and_sdk():
    from friTap.flow.collector import _ConnectionAttribution
    record = _ConnectionAttribution(sdk={"sdk": "Mine"})
    record.adopt_missing(_ConnectionAttribution(sdk={"sdk": "Other"}, caller_stack={"f": 1}))
    assert record.sdk == {"sdk": "Mine"} and record.caller_stack == {"f": 1}
    record.adopt_missing(_ConnectionAttribution(caller_stack={"f": 2}))
    assert record.caller_stack == {"f": 1}
