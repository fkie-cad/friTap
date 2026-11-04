"""The hand-written JSON Schemas in docs/api/schemas/ must accept real output.

* ``fritap.events-1.schema.json``: one line of the ``-j -`` JSONL stream
  (records produced by :class:`JsonlStdoutHandler` and
  :mod:`friTap.output.stdout_stream`).
* ``fritap.digest-2.schema.json``: the :func:`build_digest` document.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

import friTap.friTap as fritap_cli
from friTap.analysis.digest import SCHEMA as DIGEST_SCHEMA
from friTap.analysis.digest import build_digest
from friTap.events import DatalogEvent, ErrorEvent, EventBus, KeylogEvent
from friTap.exit_codes import EXIT_RUNTIME_ERROR
from friTap.output import stdout_stream
from friTap.output.jsonl_stdout_handler import JsonlStdoutHandler
from tests.unit.test_report_digest import (
    _http_flow,
    _json_body,
    _signal_flow,
    _write_tap,
)

jsonschema = pytest.importorskip("jsonschema")

SCHEMAS_DIR = Path(__file__).resolve().parents[3] / "docs" / "api" / "schemas"
EVENTS_SCHEMA_FILE = SCHEMAS_DIR / "fritap.events-1.schema.json"
DIGEST_SCHEMA_FILE = SCHEMAS_DIR / "fritap.digest-2.schema.json"

NSS_LINE = f"CLIENT_RANDOM {'ab' * 32} {'cd' * 48}"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _validator(path: Path):
    return jsonschema.Draft202012Validator(_load(path))


def _records(buffer: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in buffer.getvalue().splitlines()]


def _assert_valid(validator, record: dict) -> None:
    errors = [e.message for e in validator.iter_errors(record)]
    assert not errors, (record, errors)


@pytest.fixture
def claimed_stream():
    """A claimed '-j -' stream backed by a StringIO (no fd juggling)."""
    stdout_stream._reset_for_tests()
    buffer = io.StringIO()
    stdout_stream._stream = buffer
    yield buffer
    stdout_stream._reset_for_tests()


# --------------------------------------------------------------------------
# Schema files themselves
# --------------------------------------------------------------------------

@pytest.mark.parametrize("path", [EVENTS_SCHEMA_FILE, DIGEST_SCHEMA_FILE])
def test_schema_file_is_valid_draft_2020_12(path):
    schema = _load(path)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    jsonschema.Draft202012Validator.check_schema(schema)


def test_schema_consts_match_the_code():
    assert _load(EVENTS_SCHEMA_FILE)["properties"]["schema"]["const"] == stdout_stream.STREAM_SCHEMA
    assert _load(DIGEST_SCHEMA_FILE)["properties"]["schema"]["const"] == DIGEST_SCHEMA


# --------------------------------------------------------------------------
# fritap.events/1
# --------------------------------------------------------------------------

def _stream_events(include_key_material: bool) -> list[dict]:
    buffer = io.StringIO()
    handler = JsonlStdoutHandler(include_key_material=include_key_material, stream=buffer)
    handler.setup(bus := EventBus())
    bus.emit(KeylogEvent(key_data=NSS_LINE))
    bus.emit(KeylogEvent(payload={"cookie": "00", "shared_secret": "11"}))
    bus.emit(DatalogEvent(data=b"GET / HTTP/1.1\r\n", direction="write"))
    bus.emit(ErrorEvent(error="boom", description="agent failure"))
    handler.close()
    return _records(buffer)


@pytest.mark.parametrize("include_key_material", [False, True])
def test_handler_records_validate(include_key_material):
    validator = _validator(EVENTS_SCHEMA_FILE)
    records = _stream_events(include_key_material)
    assert records[0]["type"] == "stream_start" and records[-1]["type"] == "stream_end"
    for record in records:
        _assert_valid(validator, record)


def test_runtime_error_envelope_validates(claimed_stream):
    validator = _validator(EVENTS_SCHEMA_FILE)
    stdout_stream.note_runtime_error("StartupError", "refused", "use -s")
    assert stdout_stream.finish_unclosed_stream(EXIT_RUNTIME_ERROR) is True
    records = _records(claimed_stream)
    assert [r["type"] for r in records] == ["stream_start", "error", "stream_end"]
    for record in records:
        _assert_valid(validator, record)
    assert records[-1]["ended_by"] == stdout_stream.ENDED_BY_ERROR


def test_schema_ended_by_enum_matches_the_code():
    stream_end = _load(EVENTS_SCHEMA_FILE)["$defs"]["stream_end"]
    assert set(stream_end["properties"]["ended_by"]["enum"]) == set(stdout_stream._END_REASONS)


def test_usage_error_record_validates(claimed_stream, monkeypatch):
    monkeypatch.setattr(fritap_cli.sys, "argv", ["fritap", "-j", "-", "x"])
    fritap_cli._emit_json_stream_usage_error("bad flag")
    (record,) = _records(claimed_stream)
    _assert_valid(_validator(EVENTS_SCHEMA_FILE), record)


@pytest.mark.parametrize("record", [
    {"type": "stream_start"},                                        # no schema/timestamp
    {"schema": "fritap.events/1", "type": "stream_end", "timestamp": 1.0},  # no exit_code
    {"schema": "fritap.events/1", "type": "error", "timestamp": 1.0,
     "message": "m", "exit_code": 1},                                # runtime error without error_type
    {"schema": "fritap.events/1", "type": "keylog", "timestamp": 1.0, "event": "KeylogEvent",
     "redacted": True, "key_data": NSS_LINE},                        # redacted but leaking
    {"schema": "fritap.events/1", "type": "stream_end", "timestamp": 1.0,
     "exit_code": 0, "ended_by": "crashed"},                         # unknown end reason
])
def test_events_schema_rejects_malformed_records(record):
    assert not _validator(EVENTS_SCHEMA_FILE).is_valid(record)


# --------------------------------------------------------------------------
# fritap.digest/2
# --------------------------------------------------------------------------

@pytest.fixture
def digest_tap(tmp_path):
    flows = [
        _http_flow(f"user-{i}", url=f"/v1/users/{1000 + i}/profile?lang=en",
                   body=_json_body(uid=i), headers={"authorization": "Bearer tok.en.x"})
        for i in range(3)
    ]
    flows.append(_http_flow("rare-1", host="rare.example.net", method="GET",
                            url="/static/app.js", content_type="", status=404))
    flows.append(_signal_flow("sig-1"))
    return _write_tap(tmp_path / "schema.tap", flows)


def test_digest_validates(digest_tap):
    digest = build_digest(digest_tap)
    assert digest["truncated"] is False
    assert digest["findings"]["top"], "fixture should yield finding rows"
    assert any(p["messages"] for p in digest["protocols"].values())
    _assert_valid(_validator(DIGEST_SCHEMA_FILE), digest)


def test_truncated_digest_validates(digest_tap):
    digest = build_digest(digest_tap, budget_tokens=50, focus="security", protocol="tls")
    assert digest["truncated"] is not False
    _assert_valid(_validator(DIGEST_SCHEMA_FILE), digest)


def test_digest_schema_rejects_malformed_ref(digest_tap):
    digest = build_digest(digest_tap)
    next(iter(digest["protocols"].values()))["hosts"][0]["ref"] = "flow:abc"
    assert not _validator(DIGEST_SCHEMA_FILE).is_valid(digest)
