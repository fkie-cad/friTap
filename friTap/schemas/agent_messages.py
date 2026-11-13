#!/usr/bin/env python3

"""
Pydantic v2 models for agent -> host messages in friTap.

Each model corresponds to a ``contentType`` value sent by the Frida agent
(TypeScript side) to the Python host via ``send()``.  The discriminated
union ``AgentMessage`` at the bottom can be used to validate and parse
any incoming agent payload.

Field names and defaults are derived from the actual agent code in:
  - agent/util/log.ts              (console, console_dev, leveled logging)
  - agent/shared/shared_structures.ts  (sendKeylog, sendDatalog, sendWithProtocol)
  - agent/shared/shared_functions.ts   (getPortsAndAddresses -> netlog / datalog)
  - agent/ssh/libs/ssh_openssh.ts      (ssh_newkeys)
  - agent/ssh/platforms/linux/ssh_linux.ts  (ssh_key)
  - agent/ipsec/platforms/linux/ipsec_linux.ts  (ipsec_child_sa_keys, ipsec_ike_keys)
  - agent/misc/socket_tracer.ts    (netlog)
"""

from __future__ import annotations

from typing import Annotated, Dict, Literal, Optional, Union

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

class BaseAgentMessage(BaseModel):
    """Fields common to every agent message.

    ``contentType`` is the discriminator used by ``AgentMessage``.
    ``protocol`` is stamped by ``sendWithProtocol()`` and defaults
    to ``"tls"`` for messages sent via the plain ``send()`` helper.
    """

    contentType: str
    protocol: str = "tls"


# ---------------------------------------------------------------------------
# TLS / generic key & data messages
# ---------------------------------------------------------------------------

class KeylogMessage(BaseAgentMessage):
    """TLS/SSL key material (SSLKEYLOGFILE format lines).

    Emitted by ``sendKeylog()`` in ``shared_structures.ts``.
    """

    contentType: Literal["keylog"] = "keylog"
    keylog: str = ""


class DatalogMessage(BaseAgentMessage):
    """Decrypted application data captured from SSL_read / SSL_write.

    Emitted by ``sendDatalog()`` in ``shared_structures.ts``.
    Binary payload is delivered separately via Frida's second argument
    and is not part of the JSON payload itself.
    """

    contentType: Literal["datalog"] = "datalog"
    function: str = ""
    src_addr: Union[int, str] = 0
    dst_addr: Union[int, str] = 0
    src_port: int = 0
    dst_port: int = 0
    ss_family: str = "AF_INET"
    ssl_session_id: str = ""
    client_random: str = ""
    # QUIC-specific fields (optional, backward compatible)
    stream_id: Optional[int] = None
    quic_scid: str = ""
    quic_dcid: str = ""
    # HTTP/3 pre-decoded headers (Boundary-4 app-api mode, optional)
    http3_headers: Optional[list[list[str]]] = None  # decoded [[name, value], ...]
    quic_stream_type: Optional[str] = None
    # Explicit record direction ("read" | "write"), always set on QUIC records
    direction: Optional[str] = None
    # QUIC payload kind: "stream" (raw HTTP/3 stream bytes) | "body" (de-framed DATA)
    quic_payload: Optional[str] = None
    # Module that produced the record (e.g. "libmonochrome_64.so")
    library: Optional[str] = None


class ConnectionLifecycleMessage(BaseAgentMessage):
    """Connection lifecycle event (created/destroyed).

    Emitted by SSL_free / SSL_new hooks to track connection boundaries.

    METADATA IS OFFLINE-ONLY: this message intentionally carries connection
    IDENTITY + lifecycle only — no TLS handshake metadata (cipher suite, TLS
    version, SNI, ALPN). That metadata is produced exclusively by the offline
    pcap+keys -> .tap pipeline (friTap/offline/tshark.py), which has the full
    handshake. Do NOT add cipher_suite/protocol_version/server_name/alpn fields
    here, and do NOT have the agent emit them: the live MessageRouter
    (_emit_lifecycle) deliberately drops any such fields so the live and offline
    metadata sources can never drift.
    """

    contentType: Literal["connection_lifecycle"] = "connection_lifecycle"
    event: str = ""  # "created" | "destroyed" | "stream_fin"
    ssl_session_id: str = ""
    client_random: str = ""
    src_addr: Union[int, str] = 0
    dst_addr: Union[int, str] = 0
    src_port: int = 0
    dst_port: int = 0
    ss_family: str = "AF_INET"
    # QUIC-specific fields (optional, backward compatible)
    stream_id: Optional[int] = None
    quic_scid: str = ""
    quic_dcid: str = ""


# ---------------------------------------------------------------------------
# Library detection
# ---------------------------------------------------------------------------

class LibraryDetectedMessage(BaseAgentMessage):
    """Notification that a TLS/SSH/IPSec library was found.

    Sent when a supported library module is located in the target
    process address space.
    """

    contentType: Literal["library_detected"] = "library_detected"
    library: str = ""
    message: str = ""
    path: str = ""


# ---------------------------------------------------------------------------
# Console messages
# ---------------------------------------------------------------------------

class ConsoleMessage(BaseAgentMessage):
    """General console output from the agent (``log()`` helper).

    The ``console`` field carries the human-readable text.
    """

    contentType: Literal["console"] = "console"
    console: str = ""


class ConsoleDevMessage(BaseAgentMessage):
    """Developer-level console output (``devlog()`` helper).

    Only surfaced when debug mode is enabled on the host side.
    """

    contentType: Literal["console_dev"] = "console_dev"
    console_dev: str = ""


class _LeveledConsoleBase(BaseAgentMessage):
    """Shared fields for structured leveled log messages.

    Uses the leveled logging path in ``agent/util/log.ts`` which
    includes optional callsite information.
    """

    message: str = ""
    time: str = ""
    file: Optional[str] = None
    line: Optional[int] = None
    col: Optional[int] = None
    func: Optional[str] = None


class ConsoleDebugMessage(_LeveledConsoleBase):
    """Structured debug log emitted by ``devlog_debug()``."""

    contentType: Literal["console_debug"] = "console_debug"
    level: Literal["debug"] = "debug"


class ConsoleInfoMessage(_LeveledConsoleBase):
    """Structured info log emitted by ``devlog_info()``."""

    contentType: Literal["console_info"] = "console_info"
    level: Literal["info"] = "info"


class ConsoleWarnMessage(_LeveledConsoleBase):
    """Structured warning log emitted by ``devlog_warn()``."""

    contentType: Literal["console_warn"] = "console_warn"
    level: Literal["warn"] = "warn"


class ConsoleErrorMessage(_LeveledConsoleBase):
    """Structured error log emitted by ``devlog_error()``."""

    contentType: Literal["console_error"] = "console_error"
    level: Literal["error"] = "error"


# ---------------------------------------------------------------------------
# Network tracing (full capture / socket trace)
# ---------------------------------------------------------------------------

class NetlogMessage(BaseAgentMessage):
    """Raw network socket event from ``socket_tracer.ts``.

    Emitted during full-capture or socket-trace mode.  Address and port
    fields come from ``getPortsAndAddresses()``.
    """

    contentType: Literal["netlog"] = "netlog"
    function: str = ""
    src_addr: Union[int, str] = 0
    dst_addr: Union[int, str] = 0
    src_port: int = 0
    dst_port: int = 0
    ss_family: str = "AF_INET"


# ---------------------------------------------------------------------------
# SSH messages
# ---------------------------------------------------------------------------

class SSHNewKeysMessage(BaseAgentMessage):
    """SSH new-keys activation event.

    Emitted when ``ssh_newkeys_function`` fires in the OpenSSH hooks,
    indicating that new session keys have been put into use.
    """

    contentType: Literal["ssh_newkeys"] = "ssh_newkeys"
    direction: str = ""  # "client" or "server"
    message: str = ""
    protocol: str = "ssh"


class SSHKeyMessage(BaseAgentMessage):
    """Individual SSH key material extracted from OpenSSH.

    Emitted per key component (encryption key, IV, MAC key) for
    each direction (client / server).
    """

    contentType: Literal["ssh_key"] = "ssh_key"
    direction: str = ""  # "client" or "server"
    key_type: str = ""  # e.g. "SSH_ENC_KEY_C2S", "SSH_IV_S2C"
    cipher: str = ""
    key_data: str = ""
    key_len: Optional[int] = None
    iv_len: Optional[int] = None
    message: str = ""
    protocol: str = "ssh"


class SSHKeylogMessage(BaseAgentMessage):
    """Wireshark-compatible SSH keylog entry.

    Encodes the inputs to the Wireshark SSH dissector's keylog format:
    ``<32-hex-cookie> SHARED_SECRET <K-hex>``.  Wireshark performs the
    RFC 4253 §7.2 key-derivation internally — friTap must not pre-derive
    per-direction keys here.

    Emitted once per (re)keying when ``kex_derive_keys`` returns and
    both cookies (local + peer) are known.  The Python side correlates
    the pair by ``session_tag`` (the ``struct ssh*`` pointer hex).
    """

    contentType: Literal["ssh_keylog"] = "ssh_keylog"
    cookie: str = ""            # 32 hex chars (local SSH_MSG_KEXINIT cookie)
    peer_cookie: str = ""       # 32 hex chars (peer SSH_MSG_KEXINIT cookie)
    shared_secret: str = ""     # 2 * |K| hex chars
    direction: str = ""         # "client" | "server" (local process role)
    session_tag: str = ""       # `struct ssh*` pointer hex, re-key correlation
    protocol: str = "ssh"


# ---------------------------------------------------------------------------
# IPSec messages
# ---------------------------------------------------------------------------

class IPSecChildSAKeysMessage(BaseAgentMessage):
    """ESP Child SA key material from strongSwan.

    Keys dictionary maps labels like ``encr_i``, ``encr_r``,
    ``integ_i``, ``integ_r`` to hex-encoded key bytes.
    """

    contentType: Literal["ipsec_child_sa_keys"] = "ipsec_child_sa_keys"
    keys: Dict[str, str] = Field(default_factory=dict)
    message: str = ""
    protocol: str = "ipsec"


class IPSecIKEKeysMessage(BaseAgentMessage):
    """IKE SA key material from strongSwan (one per IKE_SA).

    Emitted at ``derive_ike_keys`` onLeave. ``spi_i``/``spi_r`` are the 16-hex
    lowercase SPIs in on-wire (big-endian) order; ``enc_alg``/``int_alg`` are
    IANA IKEv2 transform ids and ``enc_key_len_bits`` the negotiated key length.
    ``keys`` maps ``sk_ei``/``sk_er``/``sk_ai``/``sk_ar`` (and optionally
    ``sk_d``/``sk_pi``/``sk_pr``) to hex-encoded key bytes. These become one
    ``ikev2_decryption_table`` row for Wireshark.
    """

    contentType: Literal["ipsec_ike_keys"] = "ipsec_ike_keys"
    ike_version: int = 2
    spi_i: str = ""
    spi_r: str = ""
    enc_alg: Optional[int] = None
    enc_key_len_bits: Optional[int] = None
    int_alg: Optional[int] = None
    keys: Dict[str, str] = Field(default_factory=dict)
    message: str = ""
    protocol: str = "ipsec"


class IPSecESPKeysMessage(BaseAgentMessage):
    """ESP CHILD_SA key material from strongSwan (one per CHILD_SA direction).

    Emitted at the kernel-netlink ``add_sa``. ``spi`` is the 8-hex lowercase SPI
    in on-wire (big-endian) order; ``src``/``dst`` are IP strings or ``"*"`` and
    ``family`` is ``"IPv4"``/``"IPv6"``; ``enc_alg``/``int_alg`` are IANA
    transform ids and ``enc_key``/``int_key`` the hex-encoded key bytes (the ESP
    integrity key is empty for AEAD ciphers). Becomes one ``esp_sa`` row.
    """

    contentType: Literal["ipsec_esp_keys"] = "ipsec_esp_keys"
    spi: str = ""
    src: str = "*"
    dst: str = "*"
    family: str = "IPv4"
    enc_alg: Optional[int] = None
    int_alg: Optional[int] = None
    enc_key: str = ""
    int_key: str = ""
    protocol: str = "ipsec"


# ---------------------------------------------------------------------------
# SDK / caller attribution (opt-in, --attribute-sdk)
# ---------------------------------------------------------------------------

class CallerFrame(BaseModel):
    """One native stack frame in a :class:`CallerStackMessage`.

    ``module`` is the owning module name (empty when unknown); ``symbol`` and
    ``address`` are the symbolized name and the raw instruction address.
    """

    module: str = ""
    symbol: Optional[str] = None
    address: Optional[str] = None


class CallerStackMessage(BaseAgentMessage):
    """Calling-thread backtrace captured once per connection at the first TLS
    plaintext hook (OPT-IN via ``--attribute-sdk``; OFF by default).

    Additive, attribution-only message: it carries the SAME connection-identity
    join fields as :class:`ConnectionLifecycleMessage` plus the captured native
    and Java frames. The host joins it onto a connection by the 4-tuple first
    and falls back to ``ssl_session_id``. The agent emits it exactly once per
    SSL object; it never carries key material or plaintext.

    Optional identity fields (additive, empty/0 when the agent cannot read
    them): ``client_random`` (hex ClientHello random of the SSL object, the
    per-connection join key), ``tid`` / ``thread_name`` / ``pid`` of the
    calling thread, and ``transport_module`` (the module whose TLS hook fired).
    """

    contentType: Literal["caller_stack"] = "caller_stack"
    ssl_session_id: str = ""
    src_addr: Union[int, str] = 0
    dst_addr: Union[int, str] = 0
    src_port: int = 0
    dst_port: int = 0
    ss_family: str = "AF_INET"
    java_frames: list[str] = []
    native_frames: list[CallerFrame] = []
    client_random: str = ""
    tid: int = 0
    thread_name: str = ""
    pid: int = 0
    transport_module: str = ""


#: Lifecycle points of a Java-level HTTP request reported by ``request_context``.
RequestContextPoint = Literal[
    "start", "redirect", "response", "end", "webview_load", "webview_request",
]


class RequestContextMessage(BaseAgentMessage):
    """Java-level context of one HTTP request (Cronet / GMS Cronet / HttpEngine / WebView),
    opt-in via ``--attribute-sdk``. One per lifecycle ``event``; never carries keys, headers
    or bodies. ``negotiated_protocol`` is the HTTP ALPN; ``protocol`` stays the friTap record
    protocol.
    """

    contentType: Literal["request_context"] = "request_context"
    event: RequestContextPoint
    req_id: str
    stack_kind: Optional[str] = None  # "cronet" | "gms-cronet" | "httpengine" | "webview"
    url: Optional[str] = None
    method: Optional[str] = None
    frames: list[str] = []
    thread: Optional[str] = None
    tid: Optional[int] = None
    t_ms: Optional[float] = None  # agent Date.now() at the lifecycle point
    status: Optional[int] = None
    negotiated_protocol: Optional[str] = None
    cached: Optional[bool] = None
    error: Optional[str] = None
    webview_id: Optional[str] = None
    main_frame: Optional[bool] = None


# ---------------------------------------------------------------------------
# OHTTP messages
# ---------------------------------------------------------------------------

class OhttpPlaintextMessage(BaseAgentMessage):
    """Decrypted OHTTP inner payload from HPKE hooks.
    Binary bhttp payload is delivered as Frida's second argument (bytes)."""

    contentType: Literal["ohttp_plaintext"] = "ohttp_plaintext"
    direction: str = ""
    source: str = ""
    protocol: str = "ohttp"


# ---------------------------------------------------------------------------
# Discriminated union
# ---------------------------------------------------------------------------

AgentMessage = Annotated[
    Union[
        KeylogMessage,
        DatalogMessage,
        ConnectionLifecycleMessage,
        LibraryDetectedMessage,
        ConsoleMessage,
        ConsoleDevMessage,
        ConsoleDebugMessage,
        ConsoleInfoMessage,
        ConsoleWarnMessage,
        ConsoleErrorMessage,
        NetlogMessage,
        SSHNewKeysMessage,
        SSHKeyMessage,
        SSHKeylogMessage,
        IPSecChildSAKeysMessage,
        IPSecIKEKeysMessage,
        IPSecESPKeysMessage,
        OhttpPlaintextMessage,
        CallerStackMessage,
        RequestContextMessage,
    ],
    Field(discriminator="contentType"),
]
"""Discriminated union of all agent message types.

Usage::

    from pydantic import TypeAdapter
    from friTap.schemas.agent_messages import AgentMessage

    adapter = TypeAdapter(AgentMessage)
    msg = adapter.validate_python({"contentType": "keylog", "keylog": "CLIENT_RANDOM ..."})
"""
