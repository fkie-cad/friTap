#!/usr/bin/env python3

"""Memory-bounded, crash-safe JSON session output.

Covers :mod:`friTap.output.json_stream` and its use by
:class:`friTap.output.json_handler.JsonOutputHandler`:

* the streamed final document is byte-identical to the old in-memory output;
* a 200k-event session stays well under a tracemalloc peak budget;
* after a simulated crash (no finalize) the file is a valid skeleton, the
  sidecar holds the events, and recovery assembles them;
* finalize is idempotent;
* the target file is never 0 bytes.
"""

import json
import os
import tracemalloc

import pytest

from friTap.events import (
    DatalogEvent,
    ErrorEvent,
    KeylogEvent,
    LibraryDetectedEvent,
    SessionEvent,
)
from friTap.output.json_handler import JsonOutputHandler
from friTap.output.json_stream import (
    JsonStreamWriter,
    acquire_json_stream_writer,
    is_json_stream_open,
    recover_json_output,
    release_json_stream_writer,
)

try:
    from unittest.mock import MagicMock
except ImportError:  # pragma: no cover
    MagicMock = None


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _expected_document(session_info, sessions, connections, keys, errors, libs, stats):
    """The document the pre-streaming in-memory handler would have produced."""
    return {
        "session_info": session_info,
        "ssl_sessions": sessions,
        "connections": connections,
        "key_extractions": keys,
        "errors": errors,
        "libraries_detected": libs,
        "statistics": stats,
    }


def _handler(path, session_info):
    # Opt in to raw key material (as -k / --json-keys do) so the golden and
    # recovery checks below still see key_data; redaction is covered in
    # test_json_key_redaction.py.
    handler = JsonOutputHandler(path, session_info=dict(session_info),
                                include_key_material=True)
    handler.setup(MagicMock())
    return handler


# --------------------------------------------------------------------------- #
# golden: streamed document == old in-memory output
# --------------------------------------------------------------------------- #

def test_streamed_document_is_byte_identical_to_in_memory_output(tmp_path):
    path = str(tmp_path / "session.json")
    session_info = {"target_app": "demo", "start_time": "t0"}
    handler = _handler(path, session_info)

    handler.on_session(SessionEvent(
        timestamp=1.0, session_id="s1", event_type="started",
        cipher_suite="TLS_AES_256_GCM_SHA384", protocol_version="TLS 1.3",
        server_name="example.com"))
    handler.on_data(DatalogEvent(
        timestamp=2.0, data=b"hello", function="SSL_write",
        src_addr="10.0.0.1", src_port=5555, dst_addr="10.0.0.2", dst_port=443,
        ss_family="AF_INET", ssl_session_id="sid"))
    handler.on_keylog(KeylogEvent(timestamp=3.0, key_data="CLIENT_RANDOM aa bb"))
    handler.on_error(ErrorEvent(timestamp=4.0, error="boom", description="bad"))
    handler.on_data(DatalogEvent(
        timestamp=5.0, data=b"world!", function="SSL_read",
        src_addr="10.0.0.2", src_port=443, dst_addr="10.0.0.1", dst_port=5555,
        ss_family="AF_INET", ssl_session_id="sid"))
    handler.close()

    got = (tmp_path / "session.json").read_text()

    end_time = handler._session_info["end_time"]
    expected = _expected_document(
        {"target_app": "demo", "start_time": "t0", "end_time": end_time},
        [{"timestamp": 1.0, "session_id": "s1", "event_type": "started",
          "cipher_suite": "TLS_AES_256_GCM_SHA384", "protocol_version": "TLS 1.3",
          "server_name": "example.com"}],
        [{"timestamp": 2.0, "function": "SSL_write", "ssl_session_id": "sid",
          "src_addr": "10.0.0.1", "src_port": 5555, "dst_addr": "10.0.0.2",
          "dst_port": 443, "ss_family": "AF_INET", "data_length": 5},
         {"timestamp": 5.0, "function": "SSL_read", "ssl_session_id": "sid",
          "src_addr": "10.0.0.2", "src_port": 443, "dst_addr": "10.0.0.1",
          "dst_port": 5555, "ss_family": "AF_INET", "data_length": 6}],
        [{"timestamp": 3.0, "type": "key_extraction", "key_data": "CLIENT_RANDOM aa bb"}],
        [{"timestamp": 4.0, "description": "bad", "error": "boom", "stack": ""}],
        [],
        {"total_sessions": 1, "total_connections": 2, "total_bytes_captured": 11},
    )
    assert got == json.dumps(expected, indent=2, ensure_ascii=False)
    # And it round-trips.
    assert json.loads(got) == expected


def test_library_detection_and_memscan_findings_preserved(tmp_path):
    path = str(tmp_path / "s.json")
    handler = _handler(path, {"target_app": "x"})
    handler._on_library(LibraryDetectedEvent(timestamp=1.0, library="OpenSSL", path="/l"))
    handler._on_library(LibraryDetectedEvent(timestamp=1.0, library="OpenSSL", path="/l"))  # dedup
    handler.on_keylog(KeylogEvent(
        timestamp=2.0, protocol="memscan",
        payload={"label": "SERVER_TRAFFIC_SECRET_0", "client_random": "ab",
                 "tier": "A", "source": "heap"}))
    handler.close()

    doc = json.loads((tmp_path / "s.json").read_text())
    assert doc["libraries_detected"] == [
        {"name": "OpenSSL", "path": "/l", "detected_at": 1.0}]
    finding = doc["key_extractions"][0]
    assert finding["type"] == "memory_scan_finding"
    assert finding["label"] == "SERVER_TRAFFIC_SECRET_0"
    assert finding["tier"] == "A"


# --------------------------------------------------------------------------- #
# memory bound
# --------------------------------------------------------------------------- #

@pytest.mark.slow
def test_200k_events_stay_under_tracemalloc_budget(tmp_path):
    path = str(tmp_path / "big.json")
    handler = _handler(path, {"target_app": "big"})
    event = DatalogEvent(
        timestamp=1.0, data=b"x" * 64, function="SSL_write",
        src_addr="10.0.0.1", src_port=1, dst_addr="10.0.0.2", dst_port=443,
        ss_family="AF_INET", ssl_session_id="sid")
    key = KeylogEvent(timestamp=1.0, key_data="CLIENT_RANDOM " + "a" * 64)

    tracemalloc.start()
    for _ in range(100_000):
        handler.on_data(event)
        handler.on_keylog(key)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert peak < 32 * 1024 * 1024, f"peak {peak} bytes exceeds 32 MiB"
    # Memory is bounded but the counts are still exact.
    assert len(handler._data["connections"]) == 100_000
    assert handler._data["statistics"]["total_connections"] == 100_000
    handler.close()
    doc = json.loads((tmp_path / "big.json").read_text())
    assert len(doc["connections"]) == 100_000
    assert len(doc["key_extractions"]) == 100_000


# --------------------------------------------------------------------------- #
# crash safety + recovery
# --------------------------------------------------------------------------- #

def test_skeleton_is_valid_and_never_zero_bytes(tmp_path):
    path = str(tmp_path / "s.json")
    handler = _handler(path, {"target_app": "x"})
    # Immediately after setup, before any event, the file is valid non-empty JSON.
    assert os.path.getsize(path) > 0
    skeleton = json.loads((tmp_path / "s.json").read_text())
    assert skeleton["connections"] == []
    assert skeleton["session_info"]["target_app"] == "x"
    handler.on_data(DatalogEvent(timestamp=1.0, data=b"z", src_addr="a", dst_addr="b"))
    # Still valid and non-empty mid-run.
    assert os.path.getsize(path) > 0
    json.loads((tmp_path / "s.json").read_text())
    handler.close()


def test_simulated_crash_leaves_recoverable_skeleton_and_sidecar(tmp_path):
    path = str(tmp_path / "s.json")
    handler = _handler(path, {"target_app": "x"})
    handler.on_data(DatalogEvent(timestamp=1.0, data=b"aa", function="SSL_write",
                                 src_addr="1", dst_addr="2", dst_port=443))
    handler.on_data(DatalogEvent(timestamp=2.0, data=b"bbb", function="SSL_read",
                                 src_addr="2", dst_addr="1", dst_port=443))
    handler.on_keylog(KeylogEvent(timestamp=3.0, key_data="CLIENT_RANDOM aa bb"))

    # Simulate SIGKILL: the writer is abandoned without close()/release.
    sidecar = path + ".events.jsonl"
    assert os.path.isfile(sidecar)
    lines = [json.loads(line) for line in open(sidecar) if line.strip()]
    assert sum(1 for r in lines if r["k"] == "connections") == 2
    assert sum(1 for r in lines if r["k"] == "key_extractions") == 1

    # The on-disk file is a valid JSON skeleton.
    skeleton = json.loads((tmp_path / "s.json").read_text())
    assert skeleton["connections"] == []

    # Drop the registry reference so recovery runs standalone.
    from friTap.output import json_stream
    json_stream._registry.clear()

    assert recover_json_output(path) is True
    doc = json.loads((tmp_path / "s.json").read_text())
    assert [c["data_length"] for c in doc["connections"]] == [2, 3]
    assert doc["key_extractions"][0]["key_data"] == "CLIENT_RANDOM aa bb"
    # Recovery consumes the sidecar.
    assert not os.path.isfile(sidecar)
    # Nothing left to recover the second time.
    assert recover_json_output(path) is False


def test_recover_json_output_no_sidecar_is_noop(tmp_path):
    path = str(tmp_path / "nope.json")
    assert recover_json_output(path) is False


# --------------------------------------------------------------------------- #
# idempotent finalize / shared document
# --------------------------------------------------------------------------- #

def test_finalize_is_idempotent(tmp_path):
    path = str(tmp_path / "s.json")
    handler = _handler(path, {"target_app": "x"})
    handler.on_keylog(KeylogEvent(timestamp=1.0, key_data="CLIENT_RANDOM aa bb"))
    handler.close()
    first = (tmp_path / "s.json").read_text()
    # Second and third close() must not raise or corrupt the file.
    handler.close()
    handler.close()
    assert (tmp_path / "s.json").read_text() == first
    assert not is_json_stream_open(path)


def test_writer_bytes_in_events_do_not_break_serialisation(tmp_path):
    path = str(tmp_path / "s.json")
    writer = JsonStreamWriter(
        path, ["connections"], ["connections"], {})
    writer.data["connections"].append({"blob": b"\xff\xfe\x00raw"})
    writer.close()
    doc = json.loads((tmp_path / "s.json").read_text())
    assert "blob" in doc["connections"][0]


def test_shared_writer_refcount_keeps_file_complete(tmp_path):
    path = str(tmp_path / "s.json")

    def layout():
        return (["connections"], ["connections"], {})

    main, created_main = acquire_json_stream_writer(path, layout)
    assert created_main
    aux, created_aux = acquire_json_stream_writer(path, layout)
    assert not created_aux and aux is main

    main.data["connections"].append({"n": 1})
    aux.data["connections"].append({"n": 2})

    # Releasing one contributor still leaves a complete, valid document.
    release_json_stream_writer(aux)
    doc = json.loads((tmp_path / "s.json").read_text())
    assert [c["n"] for c in doc["connections"]] == [1, 2]
    assert is_json_stream_open(path)

    release_json_stream_writer(main)
    assert not is_json_stream_open(path)
    assert not os.path.isfile(path + ".events.jsonl")
