#!/usr/bin/env python3

"""Legacy inline message handling from ssl_logger.py.

Used when output handlers are not active (_handlers_active is False).
This preserves the original on_fritap_message inline output logic.
"""

from datetime import datetime, timezone

from ..constants import direction_label
from ..output.keylog_format import is_safe_keylog_line, warn_dropped_keylog_line

try:
    import hexdump
except ImportError:
    hexdump = None


def _legacy_json_writer(logger_instance):
    """Return the lazily-created streaming JSON writer for the legacy path.

    Bounds memory and adds crash-safety: events are appended to a
    ``<json>.events.jsonl`` sidecar instead of growing ``session_data`` lists
    without limit (see :mod:`friTap.output.json_stream`). The writer shares
    ``session_data``'s metadata (``friTap_version``/``session_info``/
    ``statistics``) by reference so counter updates and the end-time stamp are
    reflected on finalize. Returns ``None`` when JSON output is disabled or the
    file cannot be opened.
    """
    existing = getattr(logger_instance, "_legacy_json_stream", None)
    if existing is not None:
        return existing
    # json_output is a file path only: -j - is normalized to
    # OutputConfig.json_stream (the JsonlStdoutHandler), never a file here.
    if not logger_instance.json_output:
        return None
    from ..output.json_stream import acquire_json_stream_writer
    session_data = logger_instance.session_data
    stream_keys = [k for k in ("ssl_sessions", "connections", "key_extractions", "errors")
                   if isinstance(session_data.get(k), list)]
    order = list(session_data.keys())
    values = {k: v for k, v in session_data.items() if k not in stream_keys}
    try:
        writer, _created = acquire_json_stream_writer(
            logger_instance.json_output,
            lambda: (order, stream_keys, values),
        )
    except OSError as exc:
        logger_instance.logger.warning(
            "Failed to open JSON output file '%s': %s", logger_instance.json_output, exc)
        logger_instance._legacy_json_stream = None
        return None
    logger_instance._legacy_json_stream = writer
    return writer


def finalize_legacy_json(logger_instance) -> None:
    """Finalize and release the legacy streaming JSON document. Idempotent.

    Teardown code (``SSL_Logger._finalize_json_output``/the target-death path)
    can call this on every exit; a second call is a no-op.
    """
    writer = getattr(logger_instance, "_legacy_json_stream", None)
    if writer is None:
        return
    logger_instance._legacy_json_stream = None
    try:
        session_info = logger_instance.session_data.get("session_info")
        if isinstance(session_info, dict):
            session_info["end_time"] = datetime.now(timezone.utc).isoformat()
    except Exception:  # noqa: BLE001 - never break teardown
        pass
    from ..output.json_stream import release_json_stream_writer
    release_json_stream_writer(writer)


def _is_writable_keylog(line) -> bool:
    """True when the agent's keylog *line* is safe to write as ONE keylog line.

    The agent runs inside a possibly hostile process: a CR/LF/NUL in its string
    would otherwise inject forged lines into the keylog file. Unsafe values are
    dropped with a rate-limited warning.
    """
    if is_safe_keylog_line(line):
        return True
    warn_dropped_keylog_line("legacy: unsafe keylog line")
    return False


def _make_scapy_filter(src_addr, dst_addr, ss_family):
    return frozenset({
        "src_addr": src_addr,
        "dst_addr": dst_addr,
        "ss_family": ss_family,
    }.items())


def _make_display_filter(src_addr, dst_addr, src_port, dst_port, ss_family):
    return frozenset({
        "src_addr": src_addr,
        "dst_addr": dst_addr,
        "src_port": src_port,
        "dst_port": dst_port,
        "ss_family": ss_family,
    }.items())


def _add_socket_trace_entries(logger_instance, src_addr, dst_addr, payload):
    logger_instance.traced_Socket_Set.add(
        _make_display_filter(src_addr, dst_addr, payload["src_port"], payload["dst_port"], payload["ss_family"])
    )
    logger_instance.traced_scapy_socket_Set.add(
        _make_scapy_filter(src_addr, dst_addr, payload["ss_family"])
    )


def handle_startup_legacy(logger_instance, payload, script=None):
    """Handle individual startup handshake messages (pre-config_batch fallback).

    This is the legacy per-field handshake that older agent versions use.
    Modern agents use config_batch for a single round-trip.

    The terminal ``'anti'`` request is deliberately *not* handled here anymore:
    it now lives in ``SSL_Logger._answer_startup_handshake`` together with
    ``'config_batch'``, so that a single owner decides which script a blocking
    handshake is answered on. Reaching this function at all already implies
    that responder let the payload through.

    Args:
        logger_instance: The SSL_Logger instance (self)
        payload: The string payload from the agent (e.g., 'experimental', 'defaultFD')
        script: The script that asked. Defaults to ``logger_instance.script``,
            which is only correct while a single script exists.

    Returns:
        True if ``payload`` named a legacy channel and was answered, so callers
        can tell an answered handshake from a string they must keep routing.
    """
    target = script if script is not None else logger_instance.script
    startup_responses = {
        'experimental': ('experimental', logger_instance.experimental),
        'defaultFD': ('defaultFD', logger_instance.enable_default_fd),
        'socket_tracing': ('socket_tracing', logger_instance.socket_trace),
        'pattern_hooking': ('pattern_hooking', logger_instance.pattern_data),
        'offset_hooking': ('offset_hooking', logger_instance.offsets_data),
        'install_lsass_hook': ('install_lsass_hook', logger_instance.install_lsass_hook),
        'protocol_select': ('protocol_select', logger_instance.protocol),
        'library_scan': ('library_scan', logger_instance.scan_results_data),
        'use_modern': ('use_modern', getattr(logger_instance, 'use_modern', False)),
    }
    if payload in startup_responses:
        msg_type_key, value = startup_responses[payload]
        logger_instance._backend.post_message(target, msg_type_key, value)
        return True

    return False


def handle_message_legacy(logger_instance, payload, data, message):
    """Legacy inline message handling extracted from ssl_logger.py.

    Args:
        logger_instance: The SSL_Logger instance (self)
        payload: The message payload dict
        data: The binary data from the message
        message: The full message dict
    """
    from .ssl_logger_core import get_addr_string

    if payload["contentType"] == "console":
        if payload["console"].startswith("[*]"):
            logger_instance.logger.info(payload["console"].replace("[*] ", ""))
        else:
            logger_instance.logger.info(payload["console"])

    if logger_instance.debug or logger_instance.debug_output:
        if payload["contentType"] == "console_dev" and payload.get("console_dev"):
            if len(payload["console_dev"]) > 3:
                logger_instance.logger.debug(payload["console_dev"])
        else:
            logger_instance.print_fritap_message(message, data)

    if logger_instance.verbose:
        if (payload["contentType"] == "keylog") and logger_instance.keylog:
            if not _is_writable_keylog(payload.get("keylog")):
                return
            if payload["keylog"] not in logger_instance.keydump_Set:
                logger_instance.logger.info(payload["keylog"])
                logger_instance.keydump_Set.add(payload["keylog"])
                logger_instance.keylog_file.write(payload["keylog"] + "\n")
                logger_instance.keylog_file.flush()
                if logger_instance.json_output:
                    key_entry = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "type": "key_extraction",
                        "key_data": payload["keylog"]
                    }
                    # Stream to the crash-safe sidecar instead of growing an
                    # in-memory list without bound.
                    writer = _legacy_json_writer(logger_instance)
                    if writer is not None:
                        writer.data["key_extractions"].append(key_entry)
        elif not data or len(data) == 0:
            return
        else:
            src_addr = get_addr_string(payload["src_addr"], payload["ss_family"])
            dst_addr = get_addr_string(payload["dst_addr"], payload["ss_family"])

            if not logger_instance.socket_trace and not logger_instance.full_capture:
                logger_instance.logger.info("SSL Session: " + str(payload["ssl_session_id"]))

            if logger_instance.full_capture:
                logger_instance.traced_scapy_socket_Set.add(
                    _make_scapy_filter(src_addr, dst_addr, payload["ss_family"])
                )

            if logger_instance.socket_trace:
                _add_socket_trace_entries(logger_instance, src_addr, dst_addr, payload)
                logger_instance.logger.debug(f"[socket_trace] {src_addr}:{payload['src_port']} --> {dst_addr}:{payload['dst_port']}")
            else:
                logger_instance.logger.info("[%s] %s:%d --> %s:%d" % (payload["function"], src_addr, payload["src_port"], dst_addr, payload["dst_port"]))
                if hexdump:
                    hexdump.hexdump(data)
                else:
                    logger_instance.logger.info(f"Data: {data.hex() if data else 'No data'}")

            if logger_instance.json_output:
                connection_entry = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "function": payload["function"],
                    "ssl_session_id": payload.get("ssl_session_id"),
                    "src_addr": src_addr,
                    "src_port": payload["src_port"],
                    "dst_addr": dst_addr,
                    "dst_port": payload["dst_port"],
                    "ss_family": payload["ss_family"],
                    "data_length": len(data) if data else 0
                }
                # Stream the connection event to the crash-safe sidecar; keep
                # only the (bounded) counters in memory.
                writer = _legacy_json_writer(logger_instance)
                if writer is not None:
                    writer.data["connections"].append(connection_entry)
                logger_instance.session_data["statistics"]["total_connections"] += 1
                logger_instance.session_data["statistics"]["total_bytes_captured"] += len(data) if data else 0

    if logger_instance.pcap_name and payload["contentType"] == "datalog" and not logger_instance.full_capture:
        logger_instance.pcap_obj.log_plaintext_payload(payload["ss_family"], direction_label(payload["function"], payload.get("direction")), payload["src_addr"],
                 payload["src_port"], payload["dst_addr"], payload["dst_port"], data)

    if logger_instance.live and payload["contentType"] == "datalog" and not logger_instance.full_capture:
        try:
            logger_instance.pcap_obj.log_plaintext_payload(payload["ss_family"], direction_label(payload["function"], payload.get("direction")), payload["src_addr"],
                     payload["src_port"], payload["dst_addr"], payload["dst_port"], data)
        except (BrokenPipeError, IOError):
            logger_instance.detach_with_timeout(logger_instance.process)
            logger_instance.cleanup(logger_instance.live, logger_instance.socket_trace, logger_instance.full_capture, logger_instance.debug)

    if logger_instance.keylog and payload["contentType"] == "keylog":
        if not _is_writable_keylog(payload.get("keylog")):
            return
        if payload["keylog"] not in logger_instance.keydump_Set:
            logger_instance.keylog_file.write(payload["keylog"] + "\n")
            logger_instance.keylog_file.flush()
            logger_instance.keydump_Set.add(payload["keylog"])

    if logger_instance.socket_trace or logger_instance.full_capture:
        if "src_addr" not in payload:
            return

        src_addr = get_addr_string(payload["src_addr"], payload["ss_family"])
        dst_addr = get_addr_string(payload["dst_addr"], payload["ss_family"])

        if logger_instance.socket_trace:
            _add_socket_trace_entries(logger_instance, src_addr, dst_addr, payload)
