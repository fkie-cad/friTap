#!/usr/bin/env python3

"""
Message routing for friTap.

Extracted from SSL_Logger to reduce file length.
Routes agent message payloads to the EventBus as typed events.
"""

from __future__ import annotations

import logging
from typing import get_args

from .caller_stack_shapes import (
    REQUEST_CONTEXT_FRAME_LIMIT,
    REQUEST_CONTEXT_FRAME_TEXT_LIMIT,
    REQUEST_CONTEXT_TEXT_LIMITS,
    UNTRUSTED_TEXT_LIMIT,
    bounded_strings,
    caller_stack_lookup_keys,
    capped_text,
    finite_float,
    non_negative_int,
    optional_bool,
    strict_int,
    untrusted_caller_stack,
)
from .client_random import normalize_client_random
from .connection_index import resolve_connection_key
from .constants import DIRECTION_READ, ContentType, direction_for_function
from .endpoint_pinner import EndpointPinner, RecordEndpoints, ResolvedEndpoints
from .events import (
    AGENT_DEV_ORIGIN,
    AntiTamperDetectedEvent,
    CallerStackEvent,
    ConsoleEvent,
    DatalogEvent,
    EventBus,
    HookBreadcrumbEvent,
    KeylogEvent,
    LibraryDetectedEvent,
    OhttpEvent,
    PlatformReportEvent,
    RequestContextEvent,
    SessionEvent,
)
from .legacy.ssl_logger_core import (
    coerce_port,
    resolve_ss_family,
    sanitize_raw_addr,
)
from .schemas.agent_messages import RequestContextPoint
from .ssl_logger import get_addr_string
from .text_safety import safe_terminal_text

#: Agent devlog content types routed as debug-level dev diagnostics, mapped to
#: the agent level shown in the message prefix (``devlog_debug`` keeps its
#: unprefixed console_debug route).
_AGENT_DEVLOG_LEVELS = {
    ContentType.CONSOLE_INFO: "info",
    ContentType.CONSOLE_WARN: "warn",
    ContentType.CONSOLE_ERROR: "error",
}


def _format_devlog_callsite(payload: dict) -> str:
    """``file:line func`` from the agent's flat callsite fields (each optional), escaped."""
    location = safe_terminal_text(payload.get("file") or "")
    line = payload.get("line")
    if location and line not in (None, ""):
        location = f"{location}:{safe_terminal_text(line)}"
    func = safe_terminal_text(payload.get("func") or "")
    return " ".join(part for part in (location, func) if part)


def format_devlog_prefix(agent_level: str, payload: dict) -> str:
    """``[agent <level> <file>:<line> <func>]``; callsite parts omitted when missing."""
    callsite = _format_devlog_callsite(payload)
    return f"[agent {agent_level} {callsite}]" if callsite else f"[agent {agent_level}]"


#: ``event`` values a ``request_context`` message may carry (anything else is
#: dropped); derived from the schema's ``RequestContextPoint`` literal.
REQUEST_CONTEXT_EVENTS = frozenset(get_args(RequestContextPoint))


def request_context_fields(payload: dict) -> dict:
    """The fields of a raw ``request_context`` payload, escaped, capped and
    coerced to their :class:`RequestContextEvent` types."""
    text = {name: capped_text(payload.get(name), limit)
            for name, limit in REQUEST_CONTEXT_TEXT_LIMITS.items()}
    return {
        **text,
        "frames": bounded_strings(payload.get("frames"), REQUEST_CONTEXT_FRAME_LIMIT,
                                  REQUEST_CONTEXT_FRAME_TEXT_LIMIT),
        "tid": strict_int(payload.get("tid")),
        "t_ms": finite_float(payload.get("t_ms")),
        "status": strict_int(payload.get("status")),
        "cached": optional_bool(payload.get("cached")),
        "main_frame": optional_bool(payload.get("main_frame")),
    }


def payload_protocol(payload: dict, default: str) -> str:
    """The protocol an agent message is tagged with.

    The agent (ABI >= 3) always stamps a concrete protocol: the emitting hook's
    record protocol under ``--protocol auto|all``. ``default`` -- the protocol
    the message's content type belongs to (e.g. ``"tls"`` for keylog/datalog,
    ``"ssh"`` for SSH key records) -- covers a message without a tag.
    """
    return str(payload.get("protocol") or default)


def _with_normalized_client_random(payload: dict) -> dict:
    """*payload* with ``client_random`` normalized (see
    :func:`~friTap.client_random.normalize_client_random`), so every emitter
    keys on the same form. The caller's dict is never mutated; payloads
    without the field are returned as-is.
    """
    if "client_random" not in payload:
        return payload
    return {**payload, "client_random": normalize_client_random(payload["client_random"])}


class _CanonicalProxy:
    """Minimal proxy satisfying DataCanonical canonical accessors (src, dst, protocol)."""
    __slots__ = ("src", "dst", "protocol")

    def __init__(self, src, dst, protocol: str) -> None:
        self.src = src
        self.dst = dst
        self.protocol = protocol


class MessageRouter:
    """Routes agent message payloads to typed EventBus events.

    Supports optional display filtering via set_filter(). When a filter is
    active, datalog events that don't match the filter are silently dropped.
    Keylog, lifecycle, and meta events always pass through.
    """

    def __init__(self, event_bus: "EventBus", active_protocol=None) -> None:
        self._event_bus = event_bus
        self._logger = logging.getLogger("friTap.router")
        self._data_filter = None  # Optional FilterEngine for network-level filtering
        # Option 5: sticky per-client_random tuple for TCP records, synthetic
        # when the agent sent none. Public so the pcap finalize path can read
        # its mapping table (synthetic -> real) via ``mappings()``.
        self.endpoint_pinner = EndpointPinner()
        # Render the anti-tamper banner at most once per session, even though
        # several agent code paths may emit `anti_tamper_detected` (detection +
        # loader-hook skip). Subsequent events still flow to API consumers.
        self._anti_tamper_bannered = False
        # The user-selected --protocol set (Foundation F1 multi-protocol). May be
        # given as a single name, a comma-joined string ("tls,telegram"), a
        # list/set, or None. When "telegram" is among the selection, MTProto
        # cloud keys AND Secret-Chat E2E keys are routed into ONE combined keylog
        # file (both emitted as protocol="telegram"); otherwise behaviour is
        # unchanged.
        if active_protocol is None:
            _names = []
        elif isinstance(active_protocol, str):
            _names = [p.strip() for p in active_protocol.split(",") if p.strip()]
        else:
            _names = [str(p).strip() for p in active_protocol if str(p).strip()]
        self._active_protocols = set(_names)
        # Primary retained for any single-value consumer / debugging.
        self._active_protocol = _names[0] if _names else None

    def set_filter(self, filter_engine) -> None:
        """Set a display filter engine. Only network-level fields are checked."""
        self._data_filter = filter_engine

    def route(self, payload: dict, data: bytes) -> None:
        """Parse an agent message payload and emit the corresponding event."""
        payload = _with_normalized_client_random(payload)
        content_type = payload.get("contentType")

        if content_type == "keylog" and payload.get("keylog"):
            self._emit_keylog(payload)
        elif content_type == "datalog" and (data or payload.get("http3_headers")):
            self._emit_datalog(payload, data)
        elif content_type == "library_detected":
            self._emit_library_detected(payload)
        elif content_type == ContentType.ANTI_TAMPER_DETECTED:
            self._emit_anti_tamper_detected(payload)
        elif content_type == "connection_lifecycle":
            self._emit_lifecycle(payload)
        elif content_type == "ohttp_plaintext":
            self._emit_ohttp(payload, data)
        elif content_type == ContentType.SSH_KEY:
            self._emit_ssh_key(payload)
        elif content_type == ContentType.SSH_KEYLOG:
            self._emit_ssh_keylog(payload)
        elif content_type == ContentType.SSH_NEWKEYS:
            self._emit_ssh_newkeys(payload)
        elif content_type == ContentType.IPSEC_IKE:
            self._emit_ipsec_ike_keys(payload)
        elif content_type == ContentType.IPSEC_ESP:
            self._emit_ipsec_esp_keys(payload)
        elif content_type == ContentType.MTPROTO_KEY:
            self._emit_mtproto_key(payload)
        elif content_type == ContentType.TELEGRAM_E2E_KEY:
            self._emit_telegram_e2e_key(payload)
        elif content_type == ContentType.PRIVATE_KEY_MATERIAL:
            self._emit_private_key_material(payload)
        elif content_type == ContentType.PRIVATE_PLAINTEXT and data:
            self._emit_private_plaintext(payload, data)
        elif content_type == ContentType.TELEGRAM_E2E_PLAINTEXT and data:
            self._emit_telegram_e2e_plaintext(payload, data)
        elif content_type == "console":
            self._emit_console(payload, level="info")
        elif content_type == "console_dev":
            self._emit_console_dev(payload)
        elif content_type == ContentType.CONSOLE_DEBUG or content_type in _AGENT_DEVLOG_LEVELS:
            self._emit_console_devlog(payload, _AGENT_DEVLOG_LEVELS.get(content_type))
        elif content_type == "hook_breadcrumb":
            self._emit_hook_breadcrumb(payload)
        elif content_type == ContentType.PLATFORM_REPORT:
            self._emit_platform_report(payload)
        elif content_type == ContentType.CALLER_STACK:
            self._emit_caller_stack(payload)
        elif content_type == ContentType.REQUEST_CONTEXT:
            self._emit_request_context(payload)

    def _emit_keylog(self, payload: dict) -> None:
        self._event_bus.emit(KeylogEvent(
            key_data=payload["keylog"],
            protocol=payload_protocol(payload, "tls"),
        ))

    @staticmethod
    def _resolve_addresses(payload: dict) -> tuple:
        """Extract, validate and normalize source/destination addresses.

        Every field is agent-controlled: the family is whitelisted, addresses
        are parsed as IPv4/IPv6 (anything else -- including the raw value --
        becomes the empty "missing address"), and ports are coerced to
        0..65535. An unknown family is treated like a missing one.
        """
        # A family outside the whitelist invalidates its addresses too.
        ss_family, addr_family = resolve_ss_family(payload.get("ss_family"))
        src_addr = payload.get("src_addr", "")
        dst_addr = payload.get("dst_addr", "")
        return (
            get_addr_string(src_addr, addr_family),
            coerce_port(payload.get("src_port", 0)),
            get_addr_string(dst_addr, addr_family),
            coerce_port(payload.get("dst_port", 0)),
            ss_family,
            sanitize_raw_addr(src_addr, addr_family),  # raw (validated)
            sanitize_raw_addr(dst_addr, addr_family),  # raw (validated)
        )

    def _datalog_endpoints(self, payload: dict, client_random: str,
                           direction: str) -> ResolvedEndpoints:
        """The record's endpoints after option-5 pinning (unchanged when it
        does not apply: non-TCP transport or no client_random)."""
        (src_addr_str, src_port, dst_addr_str, dst_port,
         ss_family, src_addr, dst_addr) = self._resolve_addresses(payload)
        record = RecordEndpoints(src_addr_str, src_port, dst_addr_str, dst_port,
                                 src_addr, dst_addr, ss_family)
        resolved = self.endpoint_pinner.resolve(
            client_random, payload.get("transport", "tcp"),
            direction == DIRECTION_READ, record)
        return resolved if resolved is not None else ResolvedEndpoints(
            src_addr_str, src_port, dst_addr_str, dst_port, src_addr, dst_addr, ss_family)

    @staticmethod
    def _endpoint_fields(endpoints: ResolvedEndpoints) -> dict:
        """DatalogEvent address fields (incl. the option-5 flag and observed_*)."""
        observed = endpoints.observed
        return {
            "src_addr": endpoints.src_addr, "src_port": endpoints.src_port,
            "dst_addr": endpoints.dst_addr, "dst_port": endpoints.dst_port,
            "src_addr_raw": endpoints.src_addr_raw,
            "dst_addr_raw": endpoints.dst_addr_raw,
            "ss_family": endpoints.ss_family,
            "endpoints_synthetic": endpoints.synthetic,
            "observed_src_addr": observed.src_addr if observed else "",
            "observed_src_port": observed.src_port if observed else 0,
            "observed_dst_addr": observed.dst_addr if observed else "",
            "observed_dst_port": observed.dst_port if observed else 0,
            "observed_ss_family": observed.ss_family if observed else "",
        }

    def _emit_datalog(self, payload: dict, data: bytes) -> None:
        function = payload.get("function", "")
        direction = direction_for_function(function, payload.get("direction"))
        client_random = payload.get("client_random", "")
        endpoints = self._datalog_endpoints(payload, client_random, direction)

        if self._data_filter is not None:
            if not self._passes_data_filter(
                endpoints, client_random, direction, payload_protocol(payload, "tls"),
            ):
                return

        self._event_bus.emit(DatalogEvent(
            data=data,
            function=function,
            direction=direction,
            ssl_session_id=str(payload.get("ssl_session_id", "")),
            client_random=client_random,
            transport=payload.get("transport", "tcp"),
            http3_headers=payload.get("http3_headers"),
            stream_id=payload.get("stream_id"),
            quic_scid=str(payload.get("quic_scid", "")),
            quic_dcid=str(payload.get("quic_dcid", "")),
            quic_stream_type=str(payload.get("quic_stream_type", "")),
            quic_payload=str(payload.get("quic_payload") or ""),
            library=str(payload.get("library") or ""),
            protocol=payload_protocol(payload, "tls"),
            **self._endpoint_fields(endpoints),
        ))

    def _emit_library_detected(self, payload: dict) -> None:
        self._event_bus.emit(LibraryDetectedEvent(
            library=payload.get("library", ""),
            path=payload.get("path", ""),
            protocol=payload_protocol(payload, "tls"),
        ))

    def _emit_anti_tamper_detected(self, payload: dict) -> None:
        """Surface a detected anti-tamper runtime (e.g. PairIP). Renders ONE
        blank-line-padded red banner to the CLI (the single presentation point;
        the agent emits only the structured signal) and emits a structured event
        so API consumers (friTap/api.py) can react programmatically."""
        name = safe_terminal_text(payload.get("name") or payload.get("library", ""))
        note = safe_terminal_text(payload.get("note", ""))
        skipped = bool(payload.get("skippedLoaderHook", False))
        reason = safe_terminal_text(payload.get("reason", "detected"))
        if not self._anti_tamper_bannered:
            self._anti_tamper_bannered = True
            from .fritap_utility import build_anti_tamper_banner
            banner = build_anti_tamper_banner(name, note, skipped, reason)
            # ERROR maps to red in CustomFormatter; _colorize opts this record in.
            self._logger.error(banner, extra={"_colorize": True})
        self._event_bus.emit(AntiTamperDetectedEvent(
            library=payload.get("library", ""),
            name=name,
            skipped_loader_hook=skipped,
        ))

    def _emit_console(self, payload: dict, level: str = "info") -> None:
        # Agent console text is printed verbatim by the console sinks: escape
        # terminal control sequences (ANSI/OSC injection) at the source.
        self._event_bus.emit(ConsoleEvent(
            message=safe_terminal_text(payload.get("console", "")),
            level=level,
        ))

    def _emit_agent_dev_console(self, message: str) -> None:
        # Agent developer diagnostics (console_dev, devlog_*) are demoted to
        # debug level and tagged with their origin: they reach --debug-log and
        # -d/-do output, never the normal console, the TUI activity log or a
        # non-debug JSONL stream. *message* must already be escaped.
        self._event_bus.emit(ConsoleEvent(
            message=message,
            level="debug",
            origin=AGENT_DEV_ORIGIN,
        ))

    def _emit_console_dev(self, payload: dict) -> None:
        self._emit_agent_dev_console(
            safe_terminal_text(payload.get("console_dev", "")))

    def _emit_console_devlog(self, payload: dict, agent_level) -> None:
        # Agent devlog_*() lines ({contentType: "console_debug" | "console_info"
        # | ..., message}) take the same debug-level path as console_dev: they
        # reach --debug-log and stay off the normal console unless debug output
        # is enabled. devlog_debug (*agent_level* None) stays unprefixed;
        # info/warn/error carry the agent's level and callsite so the real
        # severity survives in the debug log.
        message = safe_terminal_text(str(payload.get("message", "")))
        if agent_level is not None:
            message = f"{format_devlog_prefix(agent_level, payload)} {message}"
        self._emit_agent_dev_console(message)

    def _emit_hook_breadcrumb(self, payload: dict) -> None:
        # In-memory crash-attribution marker (never printed). SSL_Logger stores
        # the last one so on_detach can name the hook that was executing if the
        # target dies inside it.
        self._event_bus.emit(HookBreadcrumbEvent(
            marker=payload.get("hook_breadcrumb", ""),
        ))

    def _emit_platform_report(self, payload: dict) -> None:
        # The agent's one-shot "which platform branch did I take?" report. Kept
        # dumb on purpose: SSL_Logger owns the presentation (one unconditional
        # log line) and the --probe acknowledgement, so the router carries no
        # probe-mode policy.
        try:
            abi = int(payload.get("abi", 0) or 0)
        except (TypeError, ValueError):
            # A bundle that sends a non-numeric ABI is still worth reporting;
            # only the version number is unknown.
            abi = 0
        self._event_bus.emit(PlatformReportEvent(
            platform=safe_terminal_text(payload.get("platform", "")),
            target=safe_terminal_text(payload.get("target", "")),
            probe=bool(payload.get("probe", False)),
            abi=abi,
        ))

    def _emit_ssh_key(self, payload: dict) -> None:
        """Format an SSH per-direction key/IV record as one line and emit a KeylogEvent.

        Lines use the labels OpenSSH writes via friTap's cipher_init hook
        (`SSH_ENC_KEY_C2S`, `SSH_ENC_KEY_S2C`, `SSH_IV_C2S`, `SSH_IV_S2C`).
        These are NOT the Wireshark SSH dissector's wire format — they land in
        the regular keys.log for users who want raw derived key material.
        Wireshark consumption uses the side-car file produced from
        :meth:`_emit_ssh_keylog`.
        """
        key_type = payload.get("key_type", "")
        key_data = payload.get("key_data", "")
        if not key_type or not key_data:
            return
        line = f"{key_type} {key_data}"
        self._event_bus.emit(KeylogEvent(
            key_data=line,
            protocol=payload_protocol(payload, "ssh"),
        ))

    def _emit_ssh_keylog(self, payload: dict) -> None:
        """Emit a SHARED_SECRET KeylogEvent for the Wireshark SSH dissector.

        Routed to the unified :class:`KeylogOutputHandler` bound to the SSH
        :class:`SshKeylogFormatter`. The structured ``payload`` carries the
        fields that the formatter turns into ``<cookie> SHARED_SECRET <hex>``
        lines; Wireshark performs the RFC 4253 §7.2 KDF internally.
        """
        self._event_bus.emit(KeylogEvent(
            protocol="ssh",
            payload={
                "cookie": str(payload.get("cookie", "")),
                "peer_cookie": str(payload.get("peer_cookie", "")),
                "shared_secret": str(payload.get("shared_secret", "")),
                "direction": str(payload.get("direction", "")),
                "session_tag": str(payload.get("session_tag", "")),
            },
        ))

    def _emit_ipsec_ike_keys(self, payload: dict) -> None:
        """Emit a structured IKE_SA KeylogEvent (protocol ``"ipsec"``).

        Routed to the dedicated
        :class:`~friTap.output.ipsec_decryption_tables.IPsecDecryptionTableHandler`
        (bound to the :class:`~friTap.protocols.ipsec_handler.IPsecKeylogFormatter`),
        which renders one ``ikev2_decryption_table`` row. The router stays
        protocol-agnostic and forwards the fields verbatim — SPIs and keys are
        lowercase hex already in on-wire byte order; the formatter validates and
        the writer de-duplicates. When ``-j`` is active the same event is also
        picked up by the JSON handler (subject to the key-material policy).
        """
        keys = payload.get("keys") or {}
        self._event_bus.emit(KeylogEvent(
            protocol="ipsec",
            payload={
                "record": "ike",
                "ike_version": payload.get("ike_version", 2),
                "spi_i": str(payload.get("spi_i", "")),
                "spi_r": str(payload.get("spi_r", "")),
                "enc_alg": payload.get("enc_alg"),
                "enc_key_len_bits": payload.get("enc_key_len_bits"),
                "int_alg": payload.get("int_alg"),
                "sk_ei": str(keys.get("sk_ei", "")),
                "sk_er": str(keys.get("sk_er", "")),
                "sk_ai": str(keys.get("sk_ai", "")),
                "sk_ar": str(keys.get("sk_ar", "")),
                "sk_d": str(keys.get("sk_d", "")),
                "sk_pi": str(keys.get("sk_pi", "")),
                "sk_pr": str(keys.get("sk_pr", "")),
            },
        ))

    def _emit_ipsec_esp_keys(self, payload: dict) -> None:
        """Emit a structured CHILD_SA (ESP) KeylogEvent (protocol ``"ipsec"``).

        Counterpart of :meth:`_emit_ipsec_ike_keys` for the per-direction ESP
        keys from the kernel ``add_sa``; the formatter renders one ``esp_sa``
        row. SPI and keys are lowercase hex in on-wire order (no byte-swap).
        """
        self._event_bus.emit(KeylogEvent(
            protocol="ipsec",
            payload={
                "record": "esp",
                "spi": str(payload.get("spi", "")),
                "src": str(payload.get("src", "*")),
                "dst": str(payload.get("dst", "*")),
                "family": str(payload.get("family", "IPv4")),
                "enc_alg": payload.get("enc_alg"),
                "int_alg": payload.get("int_alg"),
                "enc_key": str(payload.get("enc_key", "")),
                "int_key": str(payload.get("int_key", "")),
            },
        ))

    def _emit_mtproto_key(self, payload: dict) -> None:
        """Emit a structured MTProto auth-key KeylogEvent.

        Routed to the unified :class:`KeylogOutputHandler` bound to the
        :class:`MtprotoKeylogFormatter`, which renders the canonical
        ``MTPROTO_AUTH_KEY <dc_id> <auth_key_id> <auth_key> <key_type>`` line.

        Under ``--protocol telegram`` these cloud keys are emitted as
        ``protocol="telegram"`` so they land in the single combined Telegram
        keylog (alongside the Secret-Chat E2E keys); otherwise they keep their
        historical ``protocol="mtproto"`` routing.
        """
        protocol = "telegram" if "telegram" in self._active_protocols else "mtproto"
        auth_key = str(payload.get("auth_key", ""))
        auth_key_id = str(payload.get("auth_key_id", ""))
        # Datacenter::getAuthKey does not always populate the auth_key_id
        # out-param, but the id is by definition the low 64 bits of SHA1(auth_key).
        # Derive it here when absent so every captured temp/PFS key produces a
        # usable keylog line (the offline decryptor looks records up by this id).
        if len(auth_key_id) != 16 and len(auth_key) == 512:
            try:
                import hashlib
                auth_key_id = hashlib.sha1(bytes.fromhex(auth_key)).digest()[-8:].hex()
            except ValueError:
                pass
        self._event_bus.emit(KeylogEvent(
            protocol=protocol,
            payload={
                "auth_key_id": auth_key_id,
                "auth_key": auth_key,
                "dc_id": payload.get("dc_id", 0),
                "key_type": str(payload.get("key_type", "perm")),
            },
        ))

    def _emit_telegram_e2e_key(self, payload: dict) -> None:
        """Emit a structured Telegram Secret-Chat (E2E) key-material KeylogEvent.

        Routed to the unified :class:`KeylogOutputHandler` bound to the
        :class:`TelegramKeylogFormatter`, which renders the canonical
        ``MTPROTO_E2E_KEY <key_fingerprint> <shared_key> <chat_id>`` line into the
        SAME combined Telegram keylog as the MTProto cloud keys. Always emitted as
        ``protocol="telegram"`` (the E2E keys only exist under the Telegram
        protocol selection).
        """
        self._event_bus.emit(KeylogEvent(
            protocol="telegram",
            payload={
                "shared_key": str(payload.get("shared_key", "")),
                "key_fingerprint": str(payload.get("key_fingerprint", "")),
                "chat_id": payload.get("chat_id", 0),
            },
        ))

    def _emit_private_key_material(self, payload: dict) -> None:
        """Emit a key-material KeylogEvent for a registry-driven protocol.

        The agent tags the message with ``classifier`` (= the protocol name) and
        carries the protocol's keylog fields as plain payload entries. The router
        stays protocol-agnostic — it forwards those fields verbatim and the
        protocol's :class:`KeylogFormatter` (resolved by ``protocol``) renders the
        keylog line. Reusable by any protocol; nothing here is protocol-specific.
        """
        classifier = str(payload.get("classifier", ""))
        if not classifier:
            return
        fields = {
            k: v for k, v in payload.items()
            if k not in ("contentType", "classifier")
        }
        self._event_bus.emit(KeylogEvent(protocol=classifier, payload=fields))

    def _emit_private_plaintext(self, payload: dict, data: bytes) -> None:
        """Emit decrypted app-layer plaintext as a DatalogEvent tagged with the
        payload's ``classifier`` (= protocol name).

        Generic counterpart of :meth:`_emit_telegram_e2e_plaintext`: content
        captured out-of-band at a decrypt hook, so socket metadata is best-effort
        (the call site may not carry the 5-tuple). Protocol-agnostic.
        """
        classifier = str(payload.get("classifier", ""))
        if not classifier:
            return
        src_addr_str, src_port, dst_addr_str, dst_port, ss_family, src_addr, dst_addr = self._resolve_addresses(payload)
        self._event_bus.emit(DatalogEvent(
            data=data,
            function=str(payload.get("function", "decrypt")),
            direction=payload.get("direction", "read"),
            src_addr=src_addr_str,
            src_port=src_port,
            dst_addr=dst_addr_str,
            dst_port=dst_port,
            src_addr_raw=src_addr,
            dst_addr_raw=dst_addr,
            ss_family=ss_family,
            transport=payload.get("transport", "tcp"),
            protocol=classifier,
        ))

    def _emit_telegram_e2e_plaintext(self, payload: dict, data: bytes) -> None:
        """Emit decrypted Telegram Secret-Chat plaintext as a ``telegram_e2e``
        DatalogEvent.

        Sourced from the agent's Java-layer Secret-Chat hooks
        (``SecretChatHelper.processDecryptedObject`` /
        ``performSendEncryptedRequest``). Like the Signal path, this is
        out-of-band content captured at the SecretChatHelper boundary rather than
        by decrypting the pcap; socket metadata is best-effort (the call site may
        not carry the 5-tuple). The ``ssl_session_id`` keys live plaintext into
        its own ``telegram_e2e`` flow per Secret-Chat id — the same approach the
        offline path uses.
        """
        src_addr_str, src_port, dst_addr_str, dst_port, ss_family, src_addr, dst_addr = self._resolve_addresses(payload)
        self._event_bus.emit(DatalogEvent(
            data=data,
            function=str(payload.get("function", "")),
            direction=str(payload.get("direction", "read")),
            src_addr=src_addr_str,
            src_port=src_port,
            dst_addr=dst_addr_str,
            dst_port=dst_port,
            src_addr_raw=src_addr,
            dst_addr_raw=dst_addr,
            ss_family=ss_family,
            transport="tcp",
            protocol="telegram_e2e",
            ssl_session_id=f"telegram_e2e:{payload.get('chat_id', '')}",
        ))

    def _emit_ssh_newkeys(self, payload: dict) -> None:
        """Forward SSH newkeys activation notifications to the console handler."""
        direction = payload.get("direction", "")
        msg = payload.get("message") or f"SSH newkeys activated ({direction})"
        self._event_bus.emit(ConsoleEvent(message=msg, level="info"))

    def _emit_ohttp(self, payload: dict, data: bytes) -> None:
        self._event_bus.emit(OhttpEvent(
            data=data,
            direction=payload.get("direction", ""),
            source=payload.get("source", ""),
            protocol=payload_protocol(payload, "ohttp"),
        ))

    def _filter_candidates(self, endpoints: ResolvedEndpoints, client_random: str,
                           direction: str) -> list:
        """The tuples a record may be filtered on: its emitted (pinned) one plus,
        under a synthetic pin, the real tuple it carries (``observed``) or the
        one learned earlier for the connection.

        A synthetic-only record of a connection whose real tuple was never
        seen has only its 198.18/15 tuple, which no host/port filter on a real
        address can match -- such records are dropped by those filters, as
        before; protocol-only filters still pass them.
        """
        candidates = [endpoints]
        if not endpoints.synthetic:
            return candidates
        real = endpoints.observed or self.endpoint_pinner.learned_real(
            client_random, direction == DIRECTION_READ)
        if real is not None:
            candidates.append(real)
        return candidates

    def _passes_data_filter(self, endpoints: ResolvedEndpoints, client_random: str,
                            direction: str, protocol: str) -> bool:
        """True when the pinned OR the real endpoints of the record match."""
        return any(
            self._check_data_filter(c.src_addr, c.src_port, c.dst_addr, c.dst_port, protocol)
            for c in self._filter_candidates(endpoints, client_random, direction))

    def _check_data_filter(
        self, src_addr: str, src_port: int,
        dst_addr: str, dst_port: int, protocol: str,
    ) -> bool:
        """Check if a datalog event passes the display filter via canonical accessors."""
        try:
            from .schemas.canonical import Endpoint
            proxy = _CanonicalProxy(
                src=Endpoint(src_addr, src_port),
                dst=Endpoint(dst_addr, dst_port),
                protocol=protocol,
            )
            return self._data_filter.matches_canonical(proxy)
        except Exception:
            return True

    def _emit_caller_stack(self, payload: dict) -> None:
        """Emit a :class:`CallerStackEvent` for every ``caller_stack`` backtrace.

        The agent sends this once per connection under ``--attribute-sdk``. The
        frame strings (``java_frames``, ``native_frames[].module``) are
        attacker-controlled: :func:`~friTap.analysis.attribution.sdk.classify_frames`
        uses them purely as lookup keys, and ``sdk`` carries only the trusted
        ``{sdk, vendor, category}`` dict on a signature match (``None``
        otherwise). The frames themselves travel escaped and length-capped under
        ``untrusted`` (see :mod:`friTap.caller_stack_shapes`), so an unclassified
        stack still reaches the collector as the flow's ``caller_stack``.
        """
        java_frames, native_modules = caller_stack_lookup_keys(payload)
        sdk = self._classify_caller_stack(java_frames, native_modules)
        identity = self._caller_stack_identity(payload)
        self._log_caller_stack(identity["client_random"], payload, sdk)
        src_addr_str, src_port, dst_addr_str, dst_port, *_ = self._resolve_addresses(payload)
        self._event_bus.emit(CallerStackEvent(
            ssl_session_id=str(payload.get("ssl_session_id", "")),
            src_addr=src_addr_str,
            src_port=src_port,
            dst_addr=dst_addr_str,
            dst_port=dst_port,
            sdk=sdk,
            protocol=payload_protocol(payload, "tls"),
            untrusted=untrusted_caller_stack(payload),
            **identity,
        ))

    @staticmethod
    def _classify_caller_stack(java_frames: list, native_modules: list):
        """The trusted SDK dict for the frames, or ``None`` when nothing matches."""
        from .analysis.attribution.sdk import classify_frames

        sdk = classify_frames(java_frames=java_frames, native_modules=native_modules)
        return sdk.as_dict() if sdk is not None else None

    def _log_caller_stack(self, client_random: str, payload: dict, sdk) -> None:
        """Debug line ``caller_stack cr=<first16> native=N java=M sdk=<name|->``."""
        native = payload.get("native_frames")
        java = payload.get("java_frames")
        self._logger.debug(
            "caller_stack cr=%s native=%d java=%d sdk=%s",
            client_random[:16] or "-",
            len(native) if isinstance(native, list) else 0,
            len(java) if isinstance(java, list) else 0,
            sdk.get("sdk", "-") if sdk else "-",
        )

    @staticmethod
    def _caller_stack_identity(payload: dict) -> dict:
        """The optional connection/thread identity fields of a ``caller_stack``
        payload, coerced to their event types (missing/invalid -> empty/0).

        ``thread_name`` and ``transport_module`` come from the target, so they
        are escaped like other agent text and capped at 120 characters.
        """
        return {
            "client_random": payload.get("client_random", ""),
            "tid": non_negative_int(payload.get("tid")),
            "thread_name": capped_text(payload.get("thread_name"), UNTRUSTED_TEXT_LIMIT),
            "pid": non_negative_int(payload.get("pid")),
            "transport_module": capped_text(
                payload.get("transport_module"), UNTRUSTED_TEXT_LIMIT),
        }

    def _emit_request_context(self, payload: dict) -> None:
        """Emit a :class:`RequestContextEvent`; strings escaped and capped,
        malformed payloads dropped without raising."""
        event, req_id = payload.get("event"), payload.get("req_id")
        known_event = isinstance(event, str) and event in REQUEST_CONTEXT_EVENTS
        if not known_event or not isinstance(req_id, str) or not req_id:
            self._logger.debug(
                "request_context dropped: invalid event/req_id (event=%s)",
                capped_text(event, UNTRUSTED_TEXT_LIMIT) or "-")
            return
        self._event_bus.emit(RequestContextEvent(
            event=event,
            protocol=payload_protocol(payload, "tls"),
            **request_context_fields(payload),
        ))

    def _emit_lifecycle(self, payload: dict) -> None:
        src_addr_str, src_port, dst_addr_str, dst_port, *_ = self._resolve_addresses(payload)
        # connection_index.resolve_connection_key is the single source of truth
        # for connection keying. FlowCollector.on_data uses the very same helper
        # for DatalogEvents, so lifecycle keys and data keys agree by sharing
        # this function — there is no duplicated construction left to "keep in
        # sync". We MUST pass the same ``protocol`` both sites derive for a
        # connection (here from the payload, there from the event) so that, e.g.
        # a QUIC connection produces a ``cr:quic:...`` / ``sid:quic:...`` /
        # ``net:quic:...`` key on BOTH paths instead of a mismatched ``tls`` key
        # on one side. (The agent stamps both lifecycle and datalog messages via
        # sendWithProtocol, i.e. with the same selected protocol.)
        # The same coerced value also rides the emitted SessionEvent below; the
        # empty/None -> "tls" coercion is ALSO enforced inside
        # resolve_connection_key, so the two paths can never key differently.
        protocol = payload_protocol(payload, "tls")
        client_random = payload.get("client_random", "")
        conn_id = resolve_connection_key(
            src_addr_str, src_port, dst_addr_str, dst_port,
            session_token=str(payload.get("ssl_session_id", "")),
            client_random=client_random,
            protocol=protocol,
        )

        # METADATA IS OFFLINE-ONLY. The live agent path deliberately carries NO
        # TLS handshake metadata (cipher_suite/protocol_version/server_name/alpn):
        # those are produced solely by the offline pcap+keys -> .tap pipeline
        # (offline/tshark.py), where tshark has the full handshake. The live
        # SessionEvent carries ONLY connection IDENTITY + lifecycle so flows are
        # keyed/finalized; its metadata fields stay at their "" defaults. Do NOT
        # re-introduce metadata reads here — that would split the source of truth
        # and let live and offline metadata drift. (_stamp_tls_metadata still
        # consumes these fields, but only from the offline producer's events.)
        self._event_bus.emit(SessionEvent(
            session_id=str(payload.get("ssl_session_id", "")),
            event_type=payload.get("event", ""),
            client_random=client_random,
            connection_id=conn_id,
            src_addr=src_addr_str,
            src_port=src_port,
            dst_addr=dst_addr_str,
            dst_port=dst_port,
            protocol=protocol,
        ))
