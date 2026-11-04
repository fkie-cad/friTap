"""
Capture / device discovery tool registrations (live sessions via subprocess).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from friTap.agent_api.capture.runner import (
    CAPTURE_MODES,
    DEFAULT_CAPTURE_MODE,
    DEFAULT_DURATION_S,
    MAX_DURATION_S,
    MIN_DURATION_S,
)
from friTap.agent_api.capture.status import ENDED_BY_VALUES, PROTOCOL_STATUS_VALUES
from friTap.agent_api.registry import ToolSpec
from friTap.agent_api.schema import object_schema, page_params
from friTap.agent_api.services import capture as capture_service
from friTap.agent_api.services import discovery

if TYPE_CHECKING:
    from friTap.agent_api.registry import Registry

_STRING = {"type": "string"}
_SESSION_ID = {"session_id": {"type": "string", "minLength": 1,
                              "description": "Id returned by start_capture."}}
_DEVICE = {"type": "string", "minLength": 1,
           "description": "'local' (default), 'usb' (first USB device) or a Frida device id."}
_HOST = {"type": "string", "minLength": 1,
         "description": "Remote frida-server as ip:port (wins over device)."}


def _protocol_options_schema() -> dict[str, Any]:
    try:
        from friTap.agent_api.protocol_catalog import options_schema
    except ImportError:
        return {"type": "object", "description": "Per-protocol capture options."}
    return options_schema()


def capture_protocol_enum() -> list[str]:
    """Protocol names a capture can hook (T2 catalog; registry as fallback)."""
    try:
        from friTap.agent_api.protocol_catalog import capture_protocol_names
    except ImportError:
        from friTap.protocols.registry import (
            available_protocol_names as capture_protocol_names,
        )
    return list(capture_protocol_names())


def _start_params() -> dict[str, Any]:
    return object_schema({
        "target": {"type": "string", "minLength": 1,
                   "description": "App identifier, process name, pid or executable path."},
        "args": {"type": "array", "items": _STRING,
                 "description": "Arguments for a spawned executable (spawn=true only)."},
        "device": _DEVICE,
        "host": _HOST,
        "spawn": {"type": "boolean", "default": True,
                  "description": "Spawn the target (true) or attach to a running process."},
        "protocols": {"type": "array", "items": {"type": "string", "enum": capture_protocol_enum()},
                      "description": "Protocols to hook; omit for automatic detection."},
        "protocol_options": _protocol_options_schema(),
        "capture": {"type": "string", "enum": list(CAPTURE_MODES), "default": DEFAULT_CAPTURE_MODE,
                    "description": "keys: + keylog; plaintext: .tap only; full: + keylog + pcap."},
        "duration_s": {"type": "integer", "minimum": MIN_DURATION_S, "maximum": MAX_DURATION_S,
                       "default": DEFAULT_DURATION_S,
                       "description": "The capture stops cleanly after this many seconds."},
        "follow_exec": {"type": "boolean", "default": True,
                        "description": "Spawn mode: follow the target across exec()."},
    }, required=("target",))


_PROTOCOL_STATS = {"type": "object", "properties": {
    "status": {"type": "string", "enum": list(PROTOCOL_STATUS_VALUES),
               "description": "active = keys/plaintext/session records seen (in use); "
                              "idle = hooks installed but nothing seen -- under "
                              "protocols=auto hooks are speculative, so idle does NOT "
                              "mean the target uses this protocol; no_library_seen / "
                              "failed = not hooked."},
    "libraries": {"type": "array", "items": _STRING,
                  "description": "Libraries this protocol's hooks attached to."},
    "keys": {"type": "integer"},
    "data_events": {"type": "integer"}, "data_bytes": {"type": "integer"},
    "other_events": {"type": "integer",
                     "description": "Session / OHTTP / message records of this protocol."},
    "errors": {"type": "array", "items": _STRING},
    "hook_status": {"type": "string", "enum": ["attached", "no_library_seen", "failed"],
                    "description": "Hook level only (attached even when idle); "
                                   "read status for in-use."}}}

STATUS_RESULT = {"type": "object", "properties": {
    "schema": _STRING, "session_id": _STRING,
    "state": {"type": "string", "enum": ["starting", "running", "stopped", "failed"]},
    "hook_status": {"type": "string", "enum": ["attached", "no_library_seen", "failed"],
                    "description": "attached once any protocol's hooks attached (not proof "
                                   "of traffic; see protocols_in_use)."},
    "protocols_in_use": {"type": "array", "items": _STRING,
                         "description": "Protocols with keys, plaintext or session records "
                                        "(status active). The answer to 'what does the "
                                        "target use'."},
    "idle_hooks": {"type": "object", "additionalProperties": {"type": "array", "items": _STRING},
                   "description": "{protocol: libraries} hooked without any activity "
                                  "(speculative under protocols=auto; not in use)."},
    "exit_code": {"type": ["integer", "null"],
                  "description": "friTap's exit code: 0 = duration elapsed / stopped, "
                                 "3 = target exited (normal end, see ended_by)."},
    "ended_by": {"type": ["string", "null"], "enum": [*ENDED_BY_VALUES, None],
                 "description": "Why the session ended (null while active): target_exited, "
                                "duration, stopped or error. Only 'error' is a failure."},
    "records": {"type": "integer"},
    "protocols": {"type": "object", "additionalProperties": _PROTOCOL_STATS},
    "target": _STRING, "pid": {"type": ["integer", "null"]}, "elapsed_s": {"type": "number"},
    "duration_s": {"type": "integer"}, "capture": _STRING, "tap": _STRING,
    "tap_bytes": {"type": "integer"}, "keylog": _STRING, "pcap": _STRING,
    "keylog_files": {"type": "array", "items": _STRING},
    "stderr_log": _STRING, "stderr_tail": _STRING, "detach_reason": _STRING,
    "error": {"type": "object"},
    "phases": {"type": "array", "items": {"type": "object"}}}}

START_RESULT = {"type": "object", "properties": {
    "schema": _STRING, "session_id": _STRING, "state": _STRING, "tap": _STRING,
    "session_dir": _STRING, "argv": {"type": "array", "items": _STRING}}}

PHASE_RESULT = {"type": "object", "properties": {
    "schema": _STRING, "session_id": _STRING,
    "t": {"type": "number", "description": "Epoch seconds of the marker."},
    "t_rel": {"type": ["number", "null"],
              "description": "Seconds since the capture started (null if not started)."},
    "label": _STRING}}

SESSIONS_RESULT = {"type": "object", "properties": {
    "schema": _STRING, "sessions": {"type": "array", "items": {"type": "object"}}}}

DEVICES_RESULT = {"type": "object", "properties": {"schema": _STRING, "devices": {
    "type": "array", "items": {"type": "object", "properties": {
        "id": _STRING, "name": _STRING, "type": _STRING}}}}}

APPS_RESULT = {"type": "object", "properties": {
    "schema": _STRING, "device": {"type": "object"}, "total": {"type": "integer"},
    "next_cursor": _STRING, "apps": {"type": "array", "items": {"type": "object", "properties": {
        "name": _STRING, "identifier": {"type": ["string", "null"]},
        "pid": {"type": "integer"}, "kind": {"type": "string", "enum": ["app", "process"]}}}}}}


def _capture_specs() -> list[ToolSpec]:
    session_params = object_schema(_SESSION_ID, required=("session_id",))
    return [
        ToolSpec("start_capture", "Start a live capture of a target in the background; "
                 "returns a session_id.", _start_params(),
                 lambda p, ctx: capture_service.start_capture(p, ctx),
                 kind="capture", mutating=True, result_schema=START_RESULT),
        ToolSpec("capture_status", "State, hook status, protocols in use (vs. idle hooks) "
                 "and per-protocol counters of a session.", session_params,
                 lambda p, ctx: capture_service.capture_status(p["session_id"]),
                 kind="capture", result_schema=STATUS_RESULT),
        ToolSpec("stop_capture", "Stop a capture session (SIGINT, clean teardown) and return "
                 "its final status.", session_params,
                 lambda p, ctx: capture_service.stop_capture(p["session_id"]),
                 kind="capture", mutating=True, result_schema=STATUS_RESULT),
        ToolSpec("mark_phase", "Record a timestamped phase label (e.g. 'login') in a running "
                 "capture.", object_schema({**_SESSION_ID, "label": {
                     "type": "string", "minLength": 1, "maxLength": 200}},
                     required=("session_id", "label")),
                 lambda p, ctx: capture_service.mark_phase(p["session_id"], p["label"]),
                 kind="capture", mutating=True, result_schema=PHASE_RESULT),
        ToolSpec("list_sessions", "List the capture sessions of this server.",
                 object_schema({}), lambda p, ctx: capture_service.list_sessions(),
                 kind="capture", result_schema=SESSIONS_RESULT),
    ]


def _discovery_specs() -> list[ToolSpec]:
    apps_params = object_schema({
        "device": _DEVICE, "host": _HOST,
        "running": {"type": "boolean", "default": False,
                    "description": "Only list running apps/processes."},
        **page_params()})
    return [
        ToolSpec("list_devices", "List Frida devices (id, name, type) usable as capture "
                 "device.", object_schema({}), lambda p, ctx: discovery.list_devices(),
                 kind="discover", result_schema=DEVICES_RESULT),
        ToolSpec("list_apps", "List installed apps (or processes) of a device; running ones "
                 "first.", apps_params,
                 lambda p, ctx: discovery.list_apps(p.get("device"), p.get("host"),
                                                    p["running"], p["limit"], p.get("cursor")),
                 kind="discover", result_schema=APPS_RESULT),
    ]


def register_all(registry: "Registry") -> None:
    """Register the capture-side tools on ``registry``."""
    for spec in _capture_specs() + _discovery_specs():
        registry.register(spec)


__all__ = ["register_all", "capture_protocol_enum"]
