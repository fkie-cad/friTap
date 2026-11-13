"""Option 5: client_random normalizer, synthetic tuples and the EndpointPinner."""

import ipaddress
import logging

import pytest

from friTap.client_random import normalize_client_random
from friTap.connection_index import has_usable_endpoints
from friTap.endpoint_pinner import EndpointPinner, RecordEndpoints, synthetic_pair
from friTap.synthetic_endpoints import (
    is_default_fd_placeholder,
    is_synthetic_ip,
    synthetic_tuple,
)

CR_A = "ab" * 32
CR_B = "cd" * 32
REAL_CLIENT = ("10.0.0.2", 51000)
REAL_SERVER = ("93.184.216.34", 443)


def _record(src, dst, family="AF_INET"):
    return RecordEndpoints(src[0], src[1], dst[0], dst[1], src[0], dst[0], family)


def _write(client=REAL_CLIENT, server=REAL_SERVER):
    return _record(client, server)


def _read(client=REAL_CLIENT, server=REAL_SERVER):
    return _record(server, client)


EMPTY = RecordEndpoints("", 0, "", 0, "", "", "AF_INET")
PLACEHOLDER_WRITE = _record(("127.0.0.1", 1234), ("127.0.0.1", 2345))


class TestNormalizeClientRandom:
    def test_lowercases_upper_case_hex(self):
        assert normalize_client_random(CR_A.upper()) == CR_A

    def test_strips_whitespace(self):
        assert normalize_client_random(f"  {CR_A}\n") == CR_A

    @pytest.mark.parametrize("value", [
        None, "", "???", "<identify using PCAP> ", "ab" * 31, "ab" * 33,
        "zz" * 32, 1234, b"\xab" * 32, CR_A + " x",
    ])
    def test_rejects_non_client_randoms(self, value):
        assert normalize_client_random(value) == ""


class TestSyntheticTuple:
    def test_is_deterministic(self):
        assert synthetic_tuple(CR_A) == synthetic_tuple(CR_A)

    def test_ranges(self):
        for i in range(64):
            tup = synthetic_tuple(f"{i:064x}")
            assert ipaddress.IPv4Address(tup.client_ip) in ipaddress.IPv4Network("198.18.0.0/16")
            assert ipaddress.IPv4Address(tup.server_ip) in ipaddress.IPv4Network("198.19.0.0/16")
            assert 49152 <= tup.client_port <= 65535
            assert tup.server_port == 443

    def test_shared_leading_bytes_do_not_collide(self):
        # TLS 1.2 randoms start with gmt_unix_time: bytes 0-3 must not drive the tuple.
        first, second = "deadbeef" + "00" * 28, "deadbeef" + "11" * 28
        assert synthetic_tuple(first) != synthetic_tuple(second)

    def test_rejects_non_hex(self):
        with pytest.raises(ValueError):
            synthetic_tuple("not hex")


class TestAddressPredicates:
    @pytest.mark.parametrize("addr, expected", [
        ("198.18.0.1", True), ("198.19.255.255", True),
        (int(ipaddress.IPv4Address("198.18.3.4")), True),
        ("198.20.0.1", False), ("198.17.255.255", False), ("10.0.0.1", False),
        ("", False), (None, False), ("::1", False), (True, False), (-1, False),
        (" 198.18.0.1 ", True), ("198.1.2.3", False), ("198.18.bad", False),
        (0xC6120000, True), (0xC613FFFF, True), (0xC6140000, False), (2 ** 40, False),
    ])
    def test_is_synthetic_ip(self, addr, expected):
        assert is_synthetic_ip(addr) is expected

    @pytest.mark.parametrize("tuple4, expected", [
        (("127.0.0.1", 1234, "127.0.0.1", 2345), True),
        (("127.0.0.1", 2345, "127.0.0.1", 1234), True),
        ((0x7F000001, 1234, 0x7F000001, 2345), True),
        (("127.0.0.1", 1234, "127.0.0.1", 1234), False),
        (("127.0.0.1", 1234, "10.0.0.1", 2345), False),
        (("127.0.0.1", 1234, "127.0.0.1", 443), False),
    ])
    def test_is_default_fd_placeholder(self, tuple4, expected):
        assert is_default_fd_placeholder(*tuple4) is expected

    def test_synthetic_endpoints_are_not_usable(self):
        assert not has_usable_endpoints("198.18.1.2", 50000, "198.19.3.4", 443)
        assert not has_usable_endpoints("10.0.0.2", 50000, "198.19.3.4", 443)
        assert has_usable_endpoints("10.0.0.2", 50000, "93.184.216.34", 443)


class TestEndpointPinner:
    def test_first_real_tuple_is_pinned(self):
        pinner = EndpointPinner()
        first = pinner.resolve(CR_A, "tcp", False, _write())
        later = pinner.resolve(CR_A, "tcp", False, EMPTY)
        assert (later.src_addr, later.src_port) == REAL_CLIENT
        assert (later.dst_addr, later.dst_port) == REAL_SERVER
        assert not first.synthetic and not later.synthetic
        assert pinner.mappings() == []

    def test_missing_endpoints_get_a_synthetic_pin(self):
        resolved = EndpointPinner().resolve(CR_A, "tcp", False, None)
        tup = synthetic_tuple(CR_A)
        assert resolved.synthetic
        assert (resolved.src_addr_raw, resolved.src_port) == (tup.client_ip, tup.client_port)
        assert (resolved.dst_addr_raw, resolved.dst_port) == (tup.server_ip, tup.server_port)
        assert resolved.ss_family == "AF_INET"
        assert is_synthetic_ip(resolved.src_addr)

    def test_placeholder_is_replaced_by_synthetic_pin(self):
        resolved = EndpointPinner().resolve(CR_A, "tcp", False, PLACEHOLDER_WRITE)
        assert resolved.synthetic and resolved.observed is None

    def test_read_is_oriented_server_to_client(self):
        pinner = EndpointPinner()
        write = pinner.resolve(CR_A, "tcp", False, None)
        read = pinner.resolve(CR_A, "tcp", True, None)
        assert (read.src_addr, read.src_port) == (write.dst_addr, write.dst_port)
        assert (read.dst_addr, read.dst_port) == (write.src_addr, write.src_port)

    def test_real_read_pins_client_server_orientation(self):
        pinner = EndpointPinner()
        pinner.resolve(CR_A, "tcp", True, _read())
        write = pinner.resolve(CR_A, "tcp", False, EMPTY)
        assert (write.src_addr, write.src_port) == REAL_CLIENT

    def test_synthetic_pin_is_sticky_and_reports_observed(self):
        pinner = EndpointPinner()
        pinner.resolve(CR_A, "tcp", False, None)
        resolved = pinner.resolve(CR_A, "tcp", True, _read())
        assert resolved.synthetic
        assert resolved.observed == _read()

    def test_mapping_recorded_once_first_real_wins(self):
        pinner = EndpointPinner()
        pinner.resolve(CR_A, "tcp", False, None)
        pinner.resolve(CR_A, "tcp", False, _write())
        pinner.resolve(CR_A, "tcp", True, _read())  # same tuple, other direction
        pinner.resolve(CR_A, "tcp", False, _write(client=("10.0.0.2", 52000)))
        [entry] = pinner.mappings()
        assert entry.client_random == CR_A
        assert entry.synthetic == synthetic_pair(CR_A)
        assert (entry.real.client.addr, entry.real.client.port) == REAL_CLIENT
        assert (entry.real.server.addr, entry.real.server.port) == REAL_SERVER
        assert pinner.conflict_count == 1

    def test_unmapped_synthetic_pin_is_listed(self):
        pinner = EndpointPinner()
        pinner.resolve(CR_A, "tcp", False, None)
        [entry] = pinner.mappings()
        assert entry.real is None

    def test_real_pin_conflict_counted_and_logged_once(self):
        pinner = EndpointPinner()
        records = []
        handler = logging.Handler(level=logging.DEBUG)
        handler.emit = records.append
        logger = logging.getLogger("friTap.endpoint_pinner")
        logger.addHandler(handler)
        old_level = logger.level
        logger.setLevel(logging.DEBUG)
        try:
            pinner.resolve(CR_A, "tcp", False, _write())
            other = _write(client=("10.0.0.2", 52000))
            first = pinner.resolve(CR_A, "tcp", False, other)
            pinner.resolve(CR_A, "tcp", False, other)
        finally:
            logger.removeHandler(handler)
            logger.setLevel(old_level)
        assert (first.src_addr, first.src_port) == REAL_CLIENT
        assert first.observed is None
        assert pinner.conflict_count == 2
        assert len(records) == 1

    def test_lru_evicted_real_pin_is_restored_not_resynthesized(self):
        pinner = EndpointPinner(capacity=1)
        pinner.resolve(CR_A, "tcp", False, _write())
        pinner.resolve(CR_B, "tcp", False, _write(client=("10.0.0.3", 50000)))
        resolved = pinner.resolve(CR_A, "tcp", False, None)
        assert not resolved.synthetic  # evicted real pin comes back
        assert (resolved.src_addr, resolved.src_port) == REAL_CLIENT
        assert pinner.mappings() == []

    def test_real_pin_survives_default_lru_after_4096_other_connections(self):
        from friTap.endpoint_pinner import DEFAULT_PIN_CAPACITY
        pinner = EndpointPinner()
        pinner.resolve(CR_A, "tcp", False, _write())
        for index in range(DEFAULT_PIN_CAPACITY + 10):
            pinner.resolve(f"{index:064x}", "tcp", False, None)
        resolved = pinner.resolve(CR_A, "tcp", True, None)
        assert not resolved.synthetic
        assert (resolved.src_addr, resolved.src_port) == REAL_SERVER
        assert (resolved.dst_addr, resolved.dst_port) == REAL_CLIENT

    def test_evicted_real_pins_are_bounded_oldest_dropped_and_counted(self):
        pinner = EndpointPinner(capacity=1, evicted_real_capacity=1)
        pinner.resolve(CR_A, "tcp", False, _write())
        pinner.resolve(CR_B, "tcp", False, _write(client=("10.0.0.3", 50000)))
        pinner.resolve("ef" * 32, "tcp", False, None)  # evicts CR_B; CR_A dropped
        assert pinner.evicted_real_overflow_count == 1
        assert pinner.resolve(CR_A, "tcp", False, None).synthetic
        restored = pinner.resolve(CR_B, "tcp", False, None)
        assert not restored.synthetic and restored.src_port == 50000

    def test_clear_forgets_evicted_real_pins(self):
        pinner = EndpointPinner(capacity=1)
        pinner.resolve(CR_A, "tcp", False, _write())
        pinner.resolve(CR_B, "tcp", False, None)
        pinner.clear()
        assert pinner.resolve(CR_A, "tcp", False, None).synthetic
        assert pinner.evicted_real_overflow_count == 0

    def test_synthetic_pin_survives_eviction(self):
        pinner = EndpointPinner(capacity=1)
        pinner.resolve(CR_A, "tcp", False, None)
        pinner.resolve(CR_B, "tcp", False, None)
        resolved = pinner.resolve(CR_A, "tcp", False, _write())
        assert resolved.synthetic and resolved.observed == _write()

    @pytest.mark.parametrize("transport, cr", [("udp", CR_A), ("quic", CR_A), ("tcp", "")])
    def test_not_applicable(self, transport, cr):
        pinner = EndpointPinner()
        assert pinner.resolve(cr, transport, False, None) is None
        assert pinner.mappings() == []


class TestEndpointPinnerAllocationsAndCap:
    def test_pin_hit_reuses_the_cached_resolution(self):
        pinner = EndpointPinner()
        first = pinner.resolve(CR_A, "tcp", False, None)
        assert pinner.resolve(CR_A, "tcp", False, None) is first
        assert pinner.resolve(CR_A, "tcp", True, None) is pinner.resolve(CR_A, "tcp", True, None)

    def test_matching_real_tuple_hits_the_cache(self):
        pinner = EndpointPinner()
        first = pinner.resolve(CR_A, "tcp", False, _write())
        assert pinner.resolve(CR_A, "tcp", True, _read()) is pinner.resolve(CR_A, "tcp", True, _read())
        assert pinner.resolve(CR_A, "tcp", False, _write()) is first

    def test_mapping_table_is_capped_with_an_overflow_counter(self):
        pinner = EndpointPinner(mapping_capacity=1)
        pinner.resolve(CR_A, "tcp", False, None)
        overflowed = pinner.resolve(CR_B, "tcp", False, None)
        assert overflowed.synthetic
        assert [entry.client_random for entry in pinner.mappings()] == [CR_A]
        assert pinner.mapping_overflow_count == 1
        observed = pinner.resolve(CR_B, "tcp", False, _write())
        assert observed.observed == _write()
        assert pinner.mapping_overflow_count == 1

    def test_mappings_build_entries_on_demand(self):
        pinner = EndpointPinner()
        pinner.resolve(CR_A, "tcp", False, None)
        pinner.resolve(CR_A, "tcp", False, _write())
        [entry] = pinner.mappings()
        assert entry.synthetic == synthetic_pair(CR_A)
        assert entry.real.client.addr == REAL_CLIENT[0]

    def test_clear_resets_the_overflow_counter(self):
        pinner = EndpointPinner(mapping_capacity=0)
        pinner.resolve(CR_A, "tcp", False, None)
        pinner.clear()
        assert pinner.mapping_overflow_count == 0
