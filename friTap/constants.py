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
    # Google QUICHE (Chrome/Cronet) HTTP/3 incoming body: the HttpDecoder visitor
    # callback (clean de-framed body) and the raw-cleartext sequencer fallback.
    "QuicSpdyStream_OnDataFramePayload",
    "QuicStreamSequencer_OnStreamFrame",
    # Neqo (Firefox HTTP/3) stream receive
    "neqo_read_response_data",
    # SSH plaintext receive (OpenSSH packet layer)
    "ssh_packet_read_poll2",
    # Telegram MTProto: decrypted inbound server response (post AES-IGE decrypt)
    "mtproto_decrypt",
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
    # Telegram MTProto: plaintext outbound message (pre AES-IGE encrypt)
    "mtproto_encrypt",
})


# Protocol identifiers used in ParseResult / DataCanonical
PROTOCOL_HTTP1 = "HTTP/1.x"
PROTOCOL_HTTP2 = "HTTP/2"
PROTOCOL_HTTP3 = "HTTP/3"
PROTOCOL_QUIC = "quic"
PROTOCOL_QUIC_UNPROCESSED = "quic_unprocessed"
PROTOCOL_WEBSOCKET = "WebSocket"
PROTOCOL_TLS = "TLS"
PROTOCOL_SIGNAL = "Signal"
PROTOCOL_MTPROTO = "MTProto"
PROTOCOL_TELEGRAM_E2E = "Telegram-E2E"


# Agent ABI version — the contract between this Python host and the compiled
# Frida agent bundle: the config_batch field names, the ContentType values, and
# the rpc.exports surface (gracefulDetach, agentAbiVersion, ...). Bump this
# whenever that JS<->Python boundary changes in a way an older bundle would
# mis-handle. It is mirrored into the agent via dev/generate_agent_types.py so
# the loaded bundle can report its own ABI back (rpc agentAbiVersion); the host
# warns on mismatch and uses it to ABI-filter discoverable agent bundles
# (the ``fritap.agent_bundle`` entry-point group). Generic — names no protocol.
AGENT_ABI_VERSION = 1


# Maps a protocol-layer NAME (see friTap.flow.layers) to its human display
# string. Used by the layered protocol-display path so a Signal-bearing flow
# can render as e.g. "HTTP/2[Signal]" / "WebSocket[Signal]".
LAYER_DISPLAY_NAMES = {
    "http1": PROTOCOL_HTTP1,
    "http2": PROTOCOL_HTTP2,
    "http3": PROTOCOL_HTTP3,
    "websocket": PROTOCOL_WEBSOCKET,
    "signal": PROTOCOL_SIGNAL,
    "mtproto": PROTOCOL_MTPROTO,
    "telegram_e2e": PROTOCOL_TELEGRAM_E2E,
}


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
    ANTI_TAMPER_DETECTED = "anti_tamper_detected"
    SOCKET_TRACE = "socket_trace"
    SSH_KEY = "ssh_key"
    SSH_KEYLOG = "ssh_keylog"
    SSH_NEWKEYS = "ssh_newkeys"
    IPSEC_CHILD_SA = "ipsec_child_sa_keys"
    MTPROTO_KEY = "mtproto_key"
    TELEGRAM_E2E_KEY = "telegram_e2e_key"
    TELEGRAM_E2E_PLAINTEXT = "telegram_e2e_plaintext"
    # Generic key-material + plaintext channel for registry-driven / private
    # protocols. The agent tags each message with a ``classifier`` (= protocol
    # name); the public router carries no per-protocol field knowledge, so any
    # protocol (public or private) reuses this without naming it in the core.
    PRIVATE_KEY_MATERIAL = "private_key_material"
    PRIVATE_PLAINTEXT = "private_plaintext"
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
