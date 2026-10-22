"""Turn a friTap ``.tap`` file (plus a ConvertResult) into canonical JSON.

The canonical form is what the golden regression harness diffs. It must be a
pure function of the conversion *behaviour*, so every known source of
run-to-run noise is normalized here (never in friTap itself):

* META ``fritap_version``                     -> dropped
* header ``capture_start`` of an empty capture -> ``"<wallclock>"`` (time.time() fallback)
* KEYLOG record ``timestamp`` (time.time())    -> dropped, only the key lines are kept
* the per-run temp work dir in any string      -> ``"<WORK>"``

Raw bytes are reduced to sha256 digests so goldens stay small and secret-free.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
from typing import Any

WORK_PLACEHOLDER = "<WORK>"
WALLCLOCK_PLACEHOLDER = "<wallclock>"


def sha256_hex(data: bytes | None) -> str | None:
    """Digest of *data*, or None when there is no data at all."""
    if data is None:
        return None
    return hashlib.sha256(bytes(data)).hexdigest()


def _json_default(value: Any) -> Any:
    """Make the odd non-JSON value (bytes, enums, sets, dataclasses) stable."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"len": len(value), "sha256": sha256_hex(value)}
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, (set, frozenset)):
        return sorted(value, key=repr)
    if dataclasses.is_dataclass(value):
        return dataclasses.asdict(value)
    return repr(value)


def dumps(obj: Any) -> str:
    """The one canonical serialization: sorted keys, indent=1, trailing newline."""
    return json.dumps(obj, sort_keys=True, indent=1, default=_json_default,
                      ensure_ascii=False) + "\n"


def replace_work_dirs(obj: Any, work_dirs: list[str]) -> Any:
    """Recursively replace every occurrence of a temp work dir in strings."""
    if isinstance(obj, str):
        for work_dir in work_dirs:
            obj = obj.replace(work_dir, WORK_PLACEHOLDER)
        return obj
    if isinstance(obj, dict):
        return {key: replace_work_dirs(val, work_dirs) for key, val in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [replace_work_dirs(val, work_dirs) for val in obj]
    return obj


# ---------------------------------------------------------------------------
# File-level records
# ---------------------------------------------------------------------------

def canonical_header(header) -> dict | None:
    if header is None:
        return None
    data = dataclasses.asdict(header)
    if not data.get("flow_count"):
        data["capture_start"] = WALLCLOCK_PLACEHOLDER
    return data


def canonical_meta(meta) -> dict | None:
    if meta is None:
        return None
    data = dataclasses.asdict(meta)
    data.pop("fritap_version", None)
    return data


def canonical_keylog_records(reader) -> dict:
    """Key lines of every REC_KEYLOG record, in file order (timestamps dropped)."""
    from friTap.flow.tap_format import REC_KEYLOG, decode_keylog

    lines = []
    with reader._io_lock:  # same lock the reader uses for its own record walks
        for _offset, rec_type, payload, _crc in reader._iter_records(reader._data_start):
            if rec_type == REC_KEYLOG:
                key_data, _timestamp = decode_keylog(payload)
                lines.append(key_data)
    joined = "\n".join(lines).encode("utf-8", errors="replace")
    return {"count": len(lines), "sha256": sha256_hex(joined)}


# ---------------------------------------------------------------------------
# Per-flow records
# ---------------------------------------------------------------------------

def canonical_chunks(chunks) -> dict:
    """Count plus one digest per chunk over (direction, timestamp, function, data)."""
    digests = []
    for chunk in chunks:
        head = json.dumps([chunk.direction, chunk.timestamp, chunk.function])
        digests.append(sha256_hex(head.encode() + b"\0" + bytes(chunk.data)))
    return {"count": len(chunks), "sha256": digests}


def canonical_parse_result(result) -> dict | None:
    if result is None:
        return None
    data = result.to_dict(include_body=False)
    data["body_sha256"] = sha256_hex(result.body)
    data["raw_sha256"] = sha256_hex(result.raw)
    return data


def canonical_layer(layer) -> dict:
    data = {"type": type(layer).__name__, "to_dict": layer.to_dict(),
            "metadata_only": layer.metadata_only,
            "data_source": layer.data.data_source}
    if layer.data.data_source == "owned":
        data["owned_read_sha256"] = sha256_hex(layer.data.read)
        data["owned_write_sha256"] = sha256_hex(layer.data.write)
    if layer._inner_parsed is not None:
        data["inner_parsed"] = canonical_parse_result(layer._inner_parsed)
    return data


def canonical_trailing(flow) -> dict:
    return {
        "write_sha256": sha256_hex(flow.trailing_bytes),
        "write_protocol": flow.trailing_protocol,
        "write_parse": canonical_parse_result(flow.trailing_parse),
        "read_sha256": sha256_hex(flow.response_trailing_bytes),
        "read_protocol": flow.response_trailing_protocol,
        "read_parse": canonical_parse_result(flow.response_trailing_parse),
    }


def canonical_flow(flow, summary: dict | None) -> dict:
    return {
        "summary": summary,
        "flow": flow.to_dict(include_bodies=False),
        "chunks": canonical_chunks(flow.chunks),
        "request": canonical_parse_result(flow.request),
        "response": canonical_parse_result(flow.response),
        "ohttp_inner_request": canonical_parse_result(flow.ohttp_inner_request),
        "ohttp_inner_response": canonical_parse_result(flow.ohttp_inner_response),
        "trailing": canonical_trailing(flow),
        "layers": [canonical_layer(layer) for layer in flow.layers],
        "findings": [f.to_dict() if hasattr(f, "to_dict") else f for f in flow.findings],
    }


# ---------------------------------------------------------------------------
# Whole-file entry points
# ---------------------------------------------------------------------------

def canonical_tap(tap_path: str) -> dict:
    """Canonical view of one .tap file read back through TapReader."""
    from friTap.flow.tap_reader import TapReader

    with TapReader(tap_path) as reader:
        summaries = {s.flow_id: s.to_dict() for s in reader.read_flow_summaries()}
        flows = sorted(reader.read_all_flows(), key=lambda f: f.flow_id)
        return {
            "header": canonical_header(reader.header),
            "meta": canonical_meta(reader.meta),
            "keylog_records": canonical_keylog_records(reader),
            "flow_count": len(flows),
            "summary_count": len(summaries),
            "flows": [canonical_flow(f, summaries.get(f.flow_id)) for f in flows],
        }


def canonical_error(exc: BaseException) -> dict:
    return {"error": {"type": type(exc).__name__, "message": str(exc)}}
