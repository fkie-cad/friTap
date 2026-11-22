#!/usr/bin/env python3

"""Pydantic v2 models for agent -> host messages, one per ``contentType``.

The discriminated union ``AgentMessage`` validates any incoming payload. Field
names and defaults mirror the agent senders in agent/util/log.ts,
agent/shared/shared_structures.ts, agent/shared/shared_functions.ts,
agent/ssh/, agent/ipsec/ and agent/misc/socket_tracer.ts.
"""

from __future__ import annotations

from typing import Annotated, Dict, Literal, Optional, Union

from pydantic import BaseModel, Field


class BaseAgentMessage(BaseModel):
    """Fields common to every agent message.

    ``contentType`` is the ``AgentMessage`` discriminator; ``protocol`` is
    stamped by ``sendWithProtocol()`` and defaults to ``"tls"``.
    """

    contentType: str
    protocol: str = "tls"


class KeylogMessage(BaseAgentMessage):
    """TLS key material (SSLKEYLOGFILE lines) from ``sendKeylog()``."""

    contentType: Literal["keylog"] = "keylog"
    keylog: str = ""


class DatalogMessage(BaseAgentMessage):
    """Decrypted SSL_read / SSL_write data from ``sendDatalog()``.

    The binary payload arrives as Frida's second argument, not in the JSON.
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
    # QUIC-specific fields (optional)
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
    # QUIC connection predates the capture (control/QPACK streams never seen)
    quic_midstream: Optional[bool] = None
    # Frame-path STREAM chunk: byte offset within the stream, and FIN when it ends the stream
    stream_offset: Optional[int] = None
    fin: Optional[bool] = None
    # Module that produced the record (e.g. "libmonochrome_64.so")
    library: Optional[str] = None
    # Ms the agent held the record before sending (QUIC bodies awaiting their stream id)
    held_ms: Optional[int] = None


class ConnectionLifecycleMessage(BaseAgentMessage):
    """Connection lifecycle event from the SSL_new / SSL_free hooks.

    Carries connection identity and lifecycle only, never handshake metadata
    (cipher suite, version, SNI, ALPN). That comes solely from the offline
    pcap+keys pipeline (friTap/offline/tshark.py); the live MessageRouter
    (_emit_lifecycle) drops such fields so the two sources cannot drift.
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
    # QUIC-specific fields (optional)
    stream_id: Optional[int] = None
    quic_scid: str = ""
    quic_dcid: str = ""


class LibraryDetectedMessage(BaseAgentMessage):
    """A supported TLS/SSH/IPSec library module was located in the target."""

    contentType: Literal["library_detected"] = "library_detected"
    library: str = ""
    message: str = ""
    path: str = ""


class ConsoleMessage(BaseAgentMessage):
    """Console text from the agent's ``log()`` helper."""

    contentType: Literal["console"] = "console"
    console: str = ""


class ConsoleDevMessage(BaseAgentMessage):
    """Developer console output (``devlog()``), shown only in host debug mode."""

    contentType: Literal["console_dev"] = "console_dev"
    console_dev: str = ""


class _LeveledConsoleBase(BaseAgentMessage):
    """Leveled log fields from agent/util/log.ts, with optional callsite."""

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


class NetlogMessage(BaseAgentMessage):
    """Socket event from ``socket_tracer.ts`` in full-capture or socket-trace mode."""

    contentType: Literal["netlog"] = "netlog"
    function: str = ""
    src_addr: Union[int, str] = 0
    dst_addr: Union[int, str] = 0
    src_port: int = 0
    dst_port: int = 0
    ss_family: str = "AF_INET"


class SSHNewKeysMessage(BaseAgentMessage):
    """New SSH session keys were put into use (OpenSSH ``ssh_newkeys_function``)."""

    contentType: Literal["ssh_newkeys"] = "ssh_newkeys"
    direction: str = ""  # "client" or "server"
    message: str = ""
    protocol: str = "ssh"


class SSHKeyMessage(BaseAgentMessage):
    """One SSH key component (encryption key, IV or MAC key) per direction."""

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

    Format: ``<32-hex-cookie> SHARED_SECRET <K-hex>``. Wireshark does the
    RFC 4253 section 7.2 derivation itself, so friTap must not pre-derive keys.

    Emitted once per (re)keying when ``kex_derive_keys`` returns and both
    cookies are known; the host pairs them by ``session_tag``.
    """

    contentType: Literal["ssh_keylog"] = "ssh_keylog"
    cookie: str = ""            # 32 hex chars (local SSH_MSG_KEXINIT cookie)
    peer_cookie: str = ""       # 32 hex chars (peer SSH_MSG_KEXINIT cookie)
    shared_secret: str = ""     # 2 * |K| hex chars
    direction: str = ""         # "client" | "server" (local process role)
    session_tag: str = ""       # `struct ssh*` pointer hex, re-key correlation
    protocol: str = "ssh"


class IPSecChildSAKeysMessage(BaseAgentMessage):
    """ESP Child SA keys from strongSwan; ``keys`` maps ``encr_i``/``encr_r``/``integ_i``/``integ_r`` to hex."""

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


class CallerFrame(BaseModel):
    """One native stack frame in a :class:`CallerStackMessage`.

    ``module`` is the owning module name (empty when unknown); ``symbol`` and
    ``address`` are the symbolized name and the raw instruction address.
    """

    module: str = ""
    symbol: Optional[str] = None
    address: Optional[str] = None


class CallerStackMessage(BaseAgentMessage):
    """Calling-thread backtrace, once per SSL object at the first TLS plaintext hook.

    Opt-in via ``--attribute-sdk``; attribution only, never keys or plaintext.
    Carries the same join fields as :class:`ConnectionLifecycleMessage` plus
    native and Java frames; the host joins by 4-tuple, then ``ssl_session_id``.
    Identity fields are empty/0 when unreadable: ``client_random`` (hex, the
    per-connection join key), ``tid``/``thread_name``/``pid`` and
    ``transport_module`` (module whose TLS hook fired).
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


class PlaintextRvas(BaseModel):
    """Module-relative addresses of a stripped BoringSSL's record API."""

    SSL_read: int
    SSL_write: int


class PlaintextPrologueHashes(BaseModel):
    """Hex SHA-256 of the first 32 bytes of each function, re-checked before reuse."""

    SSL_read: str
    SSL_write: str


class _LearnedModuleKey(BaseAgentMessage):
    """Cache key fields shared by the learned-offsets reports (``build_id|size|arch``)."""

    module: str
    build_id: str
    size: int
    arch: str
    # True when the agent accepted cached values (prologue-verified); the host refreshes last_seen.
    cache_hit: Optional[bool] = None


class PlaintextApiLearnedMessage(_LearnedModuleKey):
    """SSL_read/SSL_write found by the agent's slow locator in a module with a GNU
    build id. The host caches it under ``build_id|size|arch`` and hands it back on
    the next run; never carries key material or plaintext.
    """

    contentType: Literal["plaintext_api_learned"] = "plaintext_api_learned"
    rvas: PlaintextRvas
    prologue_sha256: PlaintextPrologueHashes


class LearnedFunction(BaseModel):
    """One named function: module-relative address plus prologue hash for re-validation."""

    rva: int
    prologue_sha256: str


class ModuleOffsetsLearnedMessage(_LearnedModuleKey):
    """Named function RVAs (``functions``, e.g. ``boringssl.ssl_log_secret``) and small
    layout ints (``layout``, e.g. struct offsets; names ending in ``Rva`` hold an RVA)
    learned for a module with a GNU build id. Cached under ``build_id|size|arch``
    beside the plaintext pair; the host keeps each valid item and drops bad ones.
    """

    contentType: Literal["module_offsets_learned"] = "module_offsets_learned"
    functions: Optional[dict[str, LearnedFunction]] = None
    layout: Optional[dict[str, int]] = None


class OhttpPlaintextMessage(BaseAgentMessage):
    """Decrypted OHTTP inner payload from HPKE hooks.
    Binary bhttp payload is delivered as Frida's second argument (bytes)."""

    contentType: Literal["ohttp_plaintext"] = "ohttp_plaintext"
    direction: str = ""
    source: str = ""
    protocol: str = "ohttp"


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
        PlaintextApiLearnedMessage,
        ModuleOffsetsLearnedMessage,
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
