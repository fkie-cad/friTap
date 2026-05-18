#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared constants used by both legacy and modern paths."""

SSL_READ = frozenset({
    "SSL_read", "wolfSSL_read", "readApplicationData", "NSS_read", "Full_read",
    "gnutls_record_recv", "PR_Read", "mbedtls_ssl_read", "s2n_recv",
    # QUIC stream/datagram receive functions
    "quiche_stream_recv", "quiche_dgram_recv",
    "msquic_stream_recv",
    "QuicSpdyStream_Readv",
    # Neqo (Firefox HTTP/3) stream receive
    "neqo_read_response_data",
    # SSH plaintext receive (OpenSSH packet layer)
    "ssh_packet_read_poll2",
})

SSL_WRITE = frozenset({
    "SSL_write", "wolfSSL_write", "writeApplicationData", "NSS_write", "Full_write",
    "gnutls_record_send", "PR_Write", "mbedtls_ssl_write", "s2n_send",
    # QUIC stream/datagram send functions
    "quiche_stream_send", "quiche_dgram_send",
    "msquic_stream_send",
    "QuicSpdyStream_WriteOrBufferBody",
    # Neqo (Firefox HTTP/3) stream send
    "neqo_send_request_body",
    # SSH plaintext send (OpenSSH packet layer)
    "ssh_packet_send2",
})


# Protocol identifiers used in ParseResult / DataCanonical
PROTOCOL_HTTP1 = "HTTP/1.x"
PROTOCOL_HTTP2 = "HTTP/2"
PROTOCOL_HTTP3 = "HTTP/3"
PROTOCOL_QUIC = "quic"
PROTOCOL_QUIC_UNPROCESSED = "quic_unprocessed"
PROTOCOL_WEBSOCKET = "WebSocket"
PROTOCOL_TLS = "TLS"


class ContentType:
    """String constants for agent message contentType field."""
    KEYLOG = "keylog"
    DATALOG = "datalog"
    CONSOLE = "console"
    CONSOLE_DEV = "console_dev"
    CONSOLE_DEBUG = "console_debug"
    CONSOLE_INFO = "console_info"
    CONSOLE_WARN = "console_warn"
    CONSOLE_ERROR = "console_error"
    LIBRARY_DETECTED = "library_detected"
    SOCKET_TRACE = "socket_trace"
    SSH_KEY = "ssh_key"
    SSH_KEYLOG = "ssh_keylog"
    SSH_NEWKEYS = "ssh_newkeys"
    IPSEC_CHILD_SA = "ipsec_child_sa_keys"
    NETLOG = "netlog"
    ERROR = "error"


# Ports used by Frida and ADB that should be excluded from captures by default.
INFRASTRUCTURE_PORTS = frozenset({
    5037,   # ADB daemon
    5555,   # ADB wireless
    27042,  # frida-server default
    27043,  # frida-server alternate
})

# Loopback addresses
LOOPBACK_ADDRS = frozenset({"127.0.0.1", "::1"})


def _build_port_exclusion(
    ports: frozenset[int] | None,
    port_template: str,
) -> str:
    ports = ports or INFRASTRUCTURE_PORTS
    if not ports:
        return ""
    parts = [port_template.format(p=p) for p in sorted(ports)]
    return "not (" + " or ".join(parts) + ")"


def build_infrastructure_bpf(ports: frozenset[int] | None = None) -> str:
    """Build a BPF filter string that excludes infrastructure ports."""
    return _build_port_exclusion(ports, "tcp port {p}")


def build_infrastructure_display_filter(ports: frozenset[int] | None = None) -> str:
    """Build a Wireshark display filter that excludes infrastructure ports."""
    return _build_port_exclusion(ports, "tcp.port == {p}")
