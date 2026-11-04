"""TapReader.iter_keylogs reads only KEYLOG payloads and seeks past the rest.

Pure Python — no device/Frida.
"""

from __future__ import annotations

import os

import pytest

from friTap.flow.tap_format import REC_KEYLOG, decode_keylog, verify_payload_crc
from friTap.flow.tap_reader import TapReader
from friTap.flow.tap_writer import TapWriter
from tests.unit._digest_helpers import KEYLOG_LINE, http_flow

BIG_BODY = b"B" * 200_000
SECOND_KEYLOG = "CLIENT_RANDOM " + "ef" * 32 + " " + "01" * 48


def _write_mixed_tap(path):
    writer = TapWriter()
    writer.open(str(path), target="test")
    writer.write_keylog(KEYLOG_LINE)
    writer.write_flow(http_flow("big-1", body=BIG_BODY))
    writer.write_flow(http_flow("big-2", body=BIG_BODY))
    writer.write_keylog(SECOND_KEYLOG)
    writer.close()
    return path


def _reference_keylogs(reader):
    """The previous behaviour: read every record, keep intact KEYLOG ones."""
    with reader._io_lock:
        payloads = [
            payload
            for _o, rec_type, payload, crc in reader._iter_records(reader._data_start)
            if rec_type == REC_KEYLOG and verify_payload_crc(payload, crc)
        ]
    return [decode_keylog(p) for p in payloads]


@pytest.fixture
def payload_reads(monkeypatch):
    sizes = []
    original = TapReader._read_payload

    def spy(self, payload_len):
        sizes.append(payload_len)
        return original(self, payload_len)

    monkeypatch.setattr(TapReader, "_read_payload", spy)
    return sizes


def test_iter_keylogs_skips_non_keylog_payloads(tmp_path, payload_reads):
    tap = _write_mixed_tap(tmp_path / "mixed.tap")
    with TapReader(str(tap)) as reader:
        payload_reads.clear()  # ignore open-time index work
        keys = [k for k, _ts in reader.iter_keylogs()]

    assert keys == [KEYLOG_LINE, SECOND_KEYLOG]
    assert len(payload_reads) == 2  # only the two KEYLOG payloads were read
    assert max(payload_reads) < len(BIG_BODY)


def test_iter_keylogs_output_matches_full_scan(tmp_path):
    tap = _write_mixed_tap(tmp_path / "mixed.tap")
    with TapReader(str(tap)) as reader:
        assert list(reader.iter_keylogs()) == _reference_keylogs(reader)


@pytest.mark.parametrize("payload", [
    b'{"key_data": 5, "timestamp": 1.0}',          # not a string
    b'{"key_data": ["x"], "timestamp": 1.0}',      # not a string
    b'[' * 100_000 + b']' * 100_000,                # deeply nested JSON
])
def test_iter_keylogs_skips_malformed_untrusted_records(tmp_path, payload):
    from friTap.flow.tap_format import encode_record

    writer = TapWriter()
    writer.open(str(tmp_path / "bad.tap"), target="test")
    writer.write_keylog(KEYLOG_LINE)
    with writer._lock:
        writer._file.write(encode_record(REC_KEYLOG, payload))
    writer.write_keylog(SECOND_KEYLOG)
    writer.close()
    with TapReader(str(tmp_path / "bad.tap")) as reader:
        keys = [k for k, _ts in reader.iter_keylogs()]
    assert keys == [KEYLOG_LINE, SECOND_KEYLOG]


def test_iter_keylogs_stops_at_truncated_skipped_record(tmp_path):
    tap = _write_mixed_tap(tmp_path / "mixed.tap")
    size = os.path.getsize(tap)
    # Cut into the second big FLOW record: the trailing keylog becomes unreachable.
    with open(tap, "r+b") as fh:
        fh.truncate(size - len(BIG_BODY) // 2)
    with TapReader(str(tap)) as reader:
        keys = [k for k, _ts in reader.iter_keylogs()]
        assert list(reader.iter_keylogs()) == _reference_keylogs(reader)
    assert keys == [KEYLOG_LINE]
