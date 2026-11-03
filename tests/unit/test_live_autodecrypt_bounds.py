"""Live auto-decrypt: the device pcap stream's ``incl_len`` is not trusted.

A corrupt or hostile tcpdump stream used to size a read with a 32-bit
``incl_len`` (up to 4 GiB) built with quadratic ``bytes +=``. Lengths above
the snaplen (capped at 262144) now end the auto-decrypt stream with one clear
error; valid streams are parsed as before.
"""

from __future__ import annotations

import io
import struct
import threading
from unittest.mock import MagicMock

from friTap.output.live_autodecrypt_handler import (
    MAX_STREAM_RECORD,
    LiveAutoDecryptHandler,
)


def _global_header(snaplen=262144, endian="<"):
    return struct.pack(f"{endian}IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, 1)


def _record(data, incl_len=None, endian="<"):
    n = len(data) if incl_len is None else incl_len
    return struct.pack(f"{endian}IIII", 1, 2, n, n) + data


class _CountingStream(io.BytesIO):
    """Records the largest read size requested."""

    def __init__(self, data):
        super().__init__(data)
        self.max_request = 0

    def read(self, n=-1):
        self.max_request = max(self.max_request, n)
        return super().read(n)


def _handler():
    handler = LiveAutoDecryptHandler()
    handler._write_idb = MagicMock()
    handler._write_epb = MagicMock()
    handler._logger = MagicMock()
    return handler


def test_valid_stream_is_parsed():
    handler = _handler()
    stream = io.BytesIO(_global_header() + _record(b"A" * 60) + _record(b"B" * 1500))

    handler._read_pcap_stream(stream)

    handler._write_idb.assert_called_once_with(1)
    payloads = [c.args[0] for c in handler._write_epb.call_args_list]
    assert payloads == [b"A" * 60, b"B" * 1500]
    assert handler._write_epb.call_args_list[0].kwargs["ts_us"] == 1_000_002
    handler._logger.error.assert_not_called()


def test_big_endian_stream_is_parsed():
    handler = _handler()
    stream = io.BytesIO(_global_header(endian=">") + _record(b"xyz", endian=">"))

    handler._read_pcap_stream(stream)

    assert handler._write_epb.call_args.args[0] == b"xyz"


def test_huge_incl_len_is_rejected_with_bounded_reads():
    handler = _handler()
    handler._subprocess = MagicMock()
    process = handler._subprocess
    stream = _CountingStream(
        _global_header() + _record(b"ok") + _record(b"\x00" * 32, incl_len=0xFFFFFFF0))

    handler._read_pcap_stream(stream)  # must not raise

    assert stream.max_request <= MAX_STREAM_RECORD
    assert handler._write_epb.call_count == 1
    handler._logger.error.assert_called_once()
    assert "corrupt pcap stream" in handler._logger.error.call_args[0][0]
    assert handler._stop_event.is_set()
    process.terminate.assert_called_once()
    assert handler._subprocess is None


def test_incl_len_above_a_small_snaplen_is_rejected():
    handler = _handler()
    stream = io.BytesIO(_global_header(snaplen=96) + _record(b"\x00" * 200))

    handler._read_pcap_stream(stream)

    handler._write_epb.assert_not_called()
    handler._logger.error.assert_called_once()


def test_snaplen_zero_falls_back_to_the_cap():
    assert LiveAutoDecryptHandler._stream_record_limit(_global_header(snaplen=0), "<") \
        == MAX_STREAM_RECORD
    assert LiveAutoDecryptHandler._stream_record_limit(
        _global_header(snaplen=2 ** 31), "<") == MAX_STREAM_RECORD


def test_truncated_tail_is_a_quiet_eof():
    handler = _handler()
    stream = io.BytesIO(_global_header() + _record(b"full") + _record(b"cut", incl_len=50))

    handler._read_pcap_stream(stream)

    assert handler._write_epb.call_count == 1
    handler._logger.error.assert_not_called()


def test_corrupt_stream_does_not_escape_the_capture_thread():
    handler = _handler()
    stream = io.BytesIO(_global_header() + _record(b"", incl_len=0xFFFFFFFF))
    handler._capture_local = lambda: handler._read_pcap_stream(stream)
    errors = []
    previous_hook = threading.excepthook
    threading.excepthook = lambda args: errors.append(args)
    try:
        thread = threading.Thread(target=handler._capture_loop)
        thread.start()
        thread.join(timeout=5)
    finally:
        threading.excepthook = previous_hook

    assert errors == []
    assert handler._stop_event.is_set()


def test_read_exact_returns_bytes_and_none_on_eof():
    assert LiveAutoDecryptHandler._read_exact(io.BytesIO(b"abcdef"), 4) == b"abcd"
    assert LiveAutoDecryptHandler._read_exact(io.BytesIO(b"ab"), 4) is None
