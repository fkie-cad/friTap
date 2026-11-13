#!/usr/bin/env python3

"""Shared constants used by both legacy and modern paths."""

# Canonical read/write classification of the agent's datalog ``function``
# labels. Every Python consumer (message router, pipeline, flow collector,
# pcap/pcapng writers) derives a record's direction from these sets via
# ``is_read_function`` / ``direction_for_function`` instead of keeping its own
# list. Add a new hook label here when the agent starts emitting it.
SSL_READ = frozenset({
    # OpenSSL / BoringSSL / LibreSSL / Cronet / GoTLS (legacy label)
    "SSL_read", "SSL_read_ex",
    "wolfSSL_read", "gnutls_record_recv", "mbedtls_ssl_read", "s2n_recv",
    "matrixSslReceivedData",
    # NSS
    "NSS_read", "PR_Read", "PR_Recv",
    # Java (BouncyCastle / Conscrypt) and the raw-socket full-capture tracer
    "readApplicationData", "Full_read",
    # Apple SecureTransport, Windows Schannel (SSPI), Go crypto/tls
    "SSLRead", "DecryptMessage", "Go_Conn_Read",
    # QUIC stream/datagram receive functions
    "quiche_stream_recv", "quiche_conn_stream_recv", "quiche_dgram_recv",
    "msquic_stream_recv",
    "QuicSpdyStream_Readv", "QuicStream_Readv", "QuicStreamSequencer_Readv",
    # Google QUICHE (Chrome/Cronet) HTTP/3 incoming body: the HttpDecoder visitor
    # callback (clean de-framed body) and the raw-cleartext sequencer fallback.
    "QuicSpdyStream_OnDataFramePayload",
    "QuicSpdyStream_OnHeadersDecoded",
    "QuicStreamSequencer_OnStreamFrame",
    # Neqo (Firefox HTTP/3) stream receive
    "neqo_read_response_data", "neqo_http3conn_read_response_data",
    # SSH plaintext receive (OpenSSH packet layer)
    "ssh_packet_read_poll2",
    # Telegram MTProto: decrypted inbound server response (post AES-IGE decrypt)
    "mtproto_decrypt",
    # Signal (libsignal Java) decrypt hooks: always incoming
    "SessionCipher.decrypt", "GroupCipher.decrypt", "SealedSessionCipher.decrypt",
})

SSL_WRITE = frozenset({
    "SSL_write", "SSL_write_ex",
    "wolfSSL_write", "gnutls_record_send", "mbedtls_ssl_write", "s2n_send",
    "matrixSslEncodeWritebuf",
    "NSS_write", "PR_Write", "PR_Send",
    "writeApplicationData", "Full_write",
    "SSLWrite", "EncryptMessage", "Go_Conn_Write",
    # QUIC stream/datagram send functions
    "quiche_stream_send", "quiche_conn_stream_send", "quiche_dgram_send",
    "msquic_stream_send",
    "QuicSpdyStream_WriteOrBufferBody", "QuicSpdyStream_WriteHeaders",
    "QuicChromiumClientStream_WriteHeaders",
    "QuicSpdySession_WriteHeadersOnHeadersStream",
    # Neqo (Firefox HTTP/3) stream send
    "neqo_send_request_body", "neqo_http3conn_send_request_body",
    # SSH plaintext send (OpenSSH packet layer)
    "ssh_packet_send2",
    # Telegram MTProto: plaintext outbound message (pre AES-IGE encrypt)
    "mtproto_encrypt",
})

# Substrings that mark an unlisted label as a receive-side hook (fallback only;
# the explicit sets above always win).
_READ_LABEL_HINTS = ("read", "recv", "receive", "decrypt")

DIRECTION_READ = "read"
DIRECTION_WRITE = "write"


def _base_function_label(function: str) -> str:
    """Strip a call-signature suffix ("SSL_read(ssl, buf, n)" -> "SSL_read")."""
    return (function or "").split("(", 1)[0].strip()


def is_read_function(function: str) -> bool:
    """True when the datalog ``function`` label is a receive-side hook."""
    base = _base_function_label(function)
    if base in SSL_READ:
        return True
    if base in SSL_WRITE:
        return False
    lowered = base.lower()
    return any(hint in lowered for hint in _READ_LABEL_HINTS)


def direction_for_function(function: str, explicit: str | None = None) -> str:
    """Direction ("read"/"write") of a datalog record.

    An explicit ``direction`` already set by the agent (MTProto, Signal, ...)
    wins; otherwise it is derived from the hooked function label.
    """
    if explicit in (DIRECTION_READ, DIRECTION_WRITE):
        return explicit
    return DIRECTION_READ if is_read_function(function) else DIRECTION_WRITE


# Canonical function labels whose read/write classification is unambiguous.
_CANONICAL_DIRECTION_LABELS = {DIRECTION_READ: "SSL_read", DIRECTION_WRITE: "SSL_write"}


def direction_label(function: str, explicit: str | None = None) -> str:
    """Function label to hand to label-based writers (``PCAP.log_plaintext_payload``).

    An explicit ``direction`` maps to the canonical "SSL_read"/"SSL_write"
    label, so hooks unknown to SSL_READ/SSL_WRITE are still written the right
    way round; otherwise the record's own *function* label is returned.
    """
    return _CANONICAL_DIRECTION_LABELS.get(explicit, function)


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
PROTOCOL_RC4 = "RC4"


# Agent ABI version — the contract between this Python host and the compiled
# Frida agent bundle: the config_batch field names, the ContentType values, and
# the rpc.exports surface (gracefulDetach, agentAbiVersion, ...). Bump this
# whenever that JS<->Python boundary changes in a way an older bundle would
# mis-handle. It is mirrored into the agent via dev/generate_agent_types.py so
# the loaded bundle can report its own ABI back (rpc agentAbiVersion); the host
# warns on mismatch and uses it to ABI-filter discoverable agent bundles
# (the ``fritap.agent_bundle`` entry-point group). Generic — names no protocol.
# 2: added the ``probe`` config_batch field and the ``platform_report``
#    content type (--probe dry-run mode). A bundle at ABI 1 ignores ``probe``
#    and installs every hook as usual, which is precisely the kind of silent
#    disagreement this number exists to make visible.
# 3: every message's ``protocol`` is a concrete protocol (never ``auto``/``all``):
#    the hook's record protocol under a meta selection, the selection otherwise;
#    a hook executor may return ``false`` (installed nothing -> no
#    ``library_detected``). An ABI-2 bundle stamps the meta selection instead.
AGENT_ABI_VERSION = 3


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
    "rc4": PROTOCOL_RC4,
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
    # IPsec/strongSwan key material. IPSEC_IKE carries the IKE_SA keys (one per
    # IKE_SA, from derive_ike_keys) and IPSEC_ESP the per-direction CHILD_SA
    # (ESP) keys (from kernel add_sa). They become the Wireshark UAT decryption
    # tables ikev2_decryption_table / esp_sa (see friTap.protocols.ipsec_handler).
    # IPSEC_CHILD_SA is the historical (pre-contract) ESP content type, kept for
    # back-compat with older agent bundles that still emit it.
    IPSEC_CHILD_SA = "ipsec_child_sa_keys"
    IPSEC_IKE = "ipsec_ike_keys"
    IPSEC_ESP = "ipsec_esp_keys"
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
    # One-shot dry-run diagnostic (--probe): the agent reports which platform
    # branch it selected and, in probe mode, stops before installing hooks.
    PLATFORM_REPORT = "platform_report"
    # Opt-in SDK/caller attribution (--attribute-sdk): the calling-thread
    # backtrace captured once per connection at the first TLS plaintext hook.
    # Additive and attribution-only; carries no key material or plaintext. The
    # host resolves it to an owning SDK and attaches it to the matching flow.
    CALLER_STACK = "caller_stack"
    # Opt-in Java request context (--attribute-sdk); attribution-only, no keys or bodies.
    REQUEST_CONTEXT = "request_context"
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


def build_loopback_exclusion() -> str:
    """Build a BPF clause that drops loopback traffic (both ends loopback).

    Mirrors ``InfrastructureFilterStage._is_loopback`` in pipeline.py: a packet
    is loopback only when *both* source and destination are loopback, so a
    host talking to 127.0.0.1 through a NAT'd/routed interface is kept.
    """
    return ("not (src net 127.0.0.0/8 and dst net 127.0.0.0/8) "
            "and not (ip6 src host ::1 and ip6 dst host ::1)")


def build_capture_bpf(
    filter_infrastructure: bool = True,
    include_loopback: bool = False,
    ports: frozenset[int] | None = None,
) -> str:
    """Build the capture-side BPF honouring --no-filter-infrastructure / --loopback.

    Returns "" when no clause applies (capture everything).
    """
    clauses = []
    if filter_infrastructure:
        clauses.append(build_infrastructure_bpf(ports))
    if not include_loopback:
        clauses.append(build_loopback_exclusion())
    return " and ".join(c for c in clauses if c)


def build_infrastructure_display_filter(ports: frozenset[int] | None = None) -> str:
    """Build a Wireshark display filter that excludes infrastructure ports."""
    return _build_port_exclusion(ports, "tcp.port == {p}")


# Meta protocol selections (``--protocol auto`` / ``all``) choose WHICH hooks
# install; they are never the protocol a captured record belongs to.
META_PROTOCOL_SELECTIONS: frozenset[str] = frozenset({"auto", "all"})
