#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Legacy inline message handling from ssl_logger.py.

Used when output handlers are not active (_handlers_active is False).
This preserves the original on_fritap_message inline output logic.
"""

from datetime import datetime, timezone

try:
    import hexdump
except ImportError:
    hexdump = None


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


def handle_message_legacy(logger_instance, payload, data, message):
    """Legacy inline message handling extracted from ssl_logger.py.

    Args:
        logger_instance: The SSL_Logger instance (self)
        payload: The message payload dict
        data: The binary data from the message
        message: The full message dict
    """
    from ..ssl_logger import get_addr_string

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
                    logger_instance.session_data["key_extractions"].append(key_entry)
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
                logger_instance.session_data["connections"].append(connection_entry)
                logger_instance.session_data["statistics"]["total_connections"] += 1
                logger_instance.session_data["statistics"]["total_bytes_captured"] += len(data) if data else 0

    if logger_instance.pcap_name and payload["contentType"] == "datalog" and not logger_instance.full_capture:
        logger_instance.pcap_obj.log_plaintext_payload(payload["ss_family"], payload["function"], payload["src_addr"],
                 payload["src_port"], payload["dst_addr"], payload["dst_port"], data)

    if logger_instance.live and payload["contentType"] == "datalog" and not logger_instance.full_capture:
        try:
            logger_instance.pcap_obj.log_plaintext_payload(payload["ss_family"], payload["function"], payload["src_addr"],
                     payload["src_port"], payload["dst_addr"], payload["dst_port"], data)
        except (BrokenPipeError, IOError):
            logger_instance.detach_with_timeout(logger_instance.process)
            logger_instance.cleanup(logger_instance.live, logger_instance.socket_trace, logger_instance.full_capture, logger_instance.debug)

    if logger_instance.keylog and payload["contentType"] == "keylog":
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
