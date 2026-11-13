"""MessageRouter wiring of option 5 (synthetic endpoints) and cr normalization."""

from friTap.connection_index import resolve_connection_key
from friTap.events import CallerStackEvent, DatalogEvent, SessionEvent
from friTap.message_router import MessageRouter
from friTap.synthetic_endpoints import is_synthetic_ip, synthetic_tuple

CR = "ab" * 32


class _Bus:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


class _RecordingFilter:
    def __init__(self):
        self.seen = []

    def matches_canonical(self, proxy):
        self.seen.append((proxy.src.addr, proxy.src.port, proxy.dst.addr, proxy.dst.port))
        return True


def _router():
    bus = _Bus()
    return MessageRouter(bus), bus


def _datalog(**fields):
    payload = {"contentType": "datalog", "function": "SSL_write"}
    payload.update(fields)
    return payload


def _datalogs(bus):
    return [e for e in bus.events if isinstance(e, DatalogEvent)]


def test_addressless_tcp_datalog_with_cr_gets_synthetic_endpoints():
    router, bus = _router()
    router.route(_datalog(client_random=CR), b"x")
    [event] = _datalogs(bus)
    tup = synthetic_tuple(CR)
    assert event.endpoints_synthetic is True
    assert (event.src_addr_raw, event.src_port) == (tup.client_ip, tup.client_port)
    assert (event.dst_addr_raw, event.dst_port) == (tup.server_ip, tup.server_port)
    assert is_synthetic_ip(event.src_addr) and event.ss_family == "AF_INET"


def test_read_record_is_flipped():
    router, bus = _router()
    router.route(_datalog(client_random=CR, function="SSL_read_ex"), b"x")
    [event] = _datalogs(bus)
    assert event.direction == "read"
    assert event.src_port == 443


def test_real_tuple_after_synthetic_pin_rides_observed_fields():
    router, bus = _router()
    router.route(_datalog(client_random=CR), b"x")
    router.route(_datalog(client_random=CR, src_addr="10.0.0.2", src_port=50000,
                          dst_addr="93.184.216.34", dst_port=443, ss_family="AF_INET"), b"y")
    second = _datalogs(bus)[1]
    assert second.endpoints_synthetic and is_synthetic_ip(second.dst_addr)
    assert (second.observed_src_addr, second.observed_src_port) == ("10.0.0.2", 50000)
    assert (second.observed_dst_addr, second.observed_dst_port) == ("93.184.216.34", 443)
    assert second.observed_ss_family == "AF_INET"
    [entry] = router.endpoint_pinner.mappings()
    assert entry.real.server.addr == "93.184.216.34"


def test_upper_case_cr_is_normalized_on_datalog():
    router, bus = _router()
    router.route(_datalog(client_random=CR.upper()), b"x")
    assert _datalogs(bus)[0].client_random == CR


def test_records_without_cr_or_on_udp_are_untouched():
    router, bus = _router()
    router.route(_datalog(client_random="???"), b"x")
    router.route(_datalog(client_random=CR, transport="udp"), b"y")
    for event in _datalogs(bus):
        assert not event.endpoints_synthetic
        assert (event.src_addr, event.src_port, event.dst_port) == ("", 0, 0)
    assert _datalogs(bus)[0].client_random == ""


def test_lifecycle_key_matches_datalog_key_across_case():
    router, bus = _router()
    router.route({"contentType": "connection_lifecycle", "event": "handshake_complete",
                  "client_random": CR.upper()}, b"")
    router.route(_datalog(client_random=CR), b"x")
    session = next(e for e in bus.events if isinstance(e, SessionEvent))
    [data] = _datalogs(bus)
    data_key = resolve_connection_key(
        data.src_addr, data.src_port, data.dst_addr, data.dst_port,
        session_token=data.ssl_session_id, client_random=data.client_random)
    assert session.client_random == CR
    assert session.connection_id == data_key == f"cr:tls:{CR}"


def test_caller_stack_cr_is_normalized():
    router, bus = _router()
    router.route({"contentType": "caller_stack", "client_random": CR.upper()}, b"")
    [event] = [e for e in bus.events if isinstance(e, CallerStackEvent)]
    assert event.client_random == CR


def test_route_does_not_mutate_the_callers_payload():
    router, _ = _router()
    payload = _datalog(client_random=CR.upper())
    router.route(payload, b"x")
    assert payload["client_random"] == CR.upper()


def test_data_filter_sees_synthetic_tuple():
    router, bus = _router()
    engine = _RecordingFilter()
    router.set_filter(engine)
    router.route(_datalog(client_random=CR), b"x")
    tup = synthetic_tuple(CR)
    [(src, src_port, dst, dst_port)] = engine.seen
    assert is_synthetic_ip(src) and is_synthetic_ip(dst)
    assert (src_port, dst_port) == (tup.client_port, 443)


# --- display filter on pinned connections (pinned OR observed real tuple) ---

_REAL = dict(src_addr="10.0.0.2", src_port=50000, dst_addr="93.184.216.34",
             dst_port=443, ss_family="AF_INET")


def _host_filter_router(expression="ip.dst == 93.184.216.34"):
    from friTap.filter.evaluator import FilterEngine
    router, bus = _router()
    router.set_filter(FilterEngine(expression))
    return router, bus


def test_filter_on_real_ip_keeps_record_whose_real_tuple_rides_observed():
    router, bus = _host_filter_router()
    router.route(_datalog(client_random=CR), b"fd-less")  # pins synthetic
    router.route(_datalog(client_random=CR, **_REAL), b"real")
    assert [e.data for e in _datalogs(bus)] == [b"real"]


def test_filter_on_real_ip_keeps_later_fdless_record_once_real_tuple_learned():
    router, bus = _host_filter_router()
    router.route(_datalog(client_random=CR), b"fd-less-1")
    router.route(_datalog(client_random=CR, **_REAL), b"real")
    router.route(_datalog(client_random=CR), b"fd-less-2")
    assert [e.data for e in _datalogs(bus)] == [b"real", b"fd-less-2"]


def test_filter_on_real_ip_matches_real_pin_directly():
    router, bus = _host_filter_router()
    router.route(_datalog(client_random=CR, **_REAL), b"real")
    router.route(_datalog(client_random=CR), b"fd-less")
    assert [e.data for e in _datalogs(bus)] == [b"real", b"fd-less"]


def test_filter_on_other_ip_drops_record_with_real_tuple():
    router, bus = _host_filter_router("ip.dst == 1.2.3.4")
    router.route(_datalog(client_random=CR), b"fd-less")
    router.route(_datalog(client_random=CR, **_REAL), b"real")
    assert _datalogs(bus) == []


def test_filter_on_real_ip_orients_learned_tuple_for_read_records():
    router, bus = _host_filter_router("ip.src == 93.184.216.34")
    router.route(_datalog(client_random=CR), b"fd-less-write")
    router.route(_datalog(client_random=CR, **_REAL), b"real-write")
    router.route(_datalog(client_random=CR, function="SSL_read"), b"fd-less-read")
    assert [e.data for e in _datalogs(bus)] == [b"fd-less-read"]
