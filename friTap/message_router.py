#!/usr/bin/env python3

"""Routes agent message payloads to the EventBus as typed events."""

from __future__ import annotations

import logging
import threading
import time
from typing import get_args

from .agent_socket_fields import (
    coerce_port,
    get_addr_string,
    resolve_ss_family,
    sanitize_raw_addr,
)
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
from .capture_time import held_capture_times
from .client_random import normalize_client_random
from .connection_index import resolve_connection_key
from .constants import DIRECTION_READ, ContentType, direction_for_function
from .endpoint_pinner import EndpointPinner, RecordEndpoints, ResolvedEndpoints
from .events import (
    AGENT_DEV_ORIGIN,
    PROCESS_ORIGIN_KEY,
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
from .schemas.agent_messages import RequestContextPoint
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
    """The protocol tag of an agent message (ABI >= 3 always stamps one); ``default`` covers an untagged message."""
    return str(payload.get("protocol") or default)


def _with_normalized_client_random(payload: dict) -> dict:
    """*payload* with ``client_random`` normalized so every emitter keys on the same form; never mutates the input."""
    if "client_random" not in payload:
        return payload
    return {**payload, "client_random": normalize_client_random(payload["client_random"])}


#: Cap for the process name / role strings of an event's process origin.
_ORIGIN_TEXT_LIMIT = 120


def _origin_text(value) -> str | None:
    return capped_text(value, _ORIGIN_TEXT_LIMIT) if isinstance(value, str) else None


def _origin_of(payload: dict) -> dict | None:
    """The ``{pid, process, role}`` the host stamped on *payload*, escaped and capped; None when absent or malformed."""
    origin = payload.get(PROCESS_ORIGIN_KEY)
    if not isinstance(origin, dict):
        return None
    pid = origin.get("pid")
    return {
        "pid": pid if isinstance(pid, int) and not isinstance(pid, bool) else None,
        "process": _origin_text(origin.get("process")),
        "role": _origin_text(origin.get("role")),
    }


class _CanonicalProxy:
    """Minimal proxy satisfying DataCanonical canonical accessors (src, dst, protocol)."""
    __slots__ = ("src", "dst", "protocol")

    def __init__(self, src, dst, protocol: str) -> None:
        self.src = src
        self.dst = dst
        self.protocol = protocol


class MessageRouter:
    """Routes agent message payloads to typed EventBus events.

    With a display filter set, non-matching datalog events are dropped;
    keylog, lifecycle and meta events always pass.
    """

    def __init__(self, event_bus: "EventBus", active_protocol=None) -> None:
        self._event_bus = event_bus
        self._logger = logging.getLogger("friTap.router")
        # Process origin of the payload being routed (per thread), stamped by _publish.
        self._routing = threading.local()
        self._data_filter = None  # Optional FilterEngine for network-level filtering
        # Receives plaintext_api_learned / module_offsets_learned payloads; None
        # drops them. A callable keeps the router free of cache I/O.
        self._learned_offsets_sink = None
        # Sticky per-client_random tuple for TCP records, synthetic when the
        # agent sent none. Public so pcap finalize can read ``mappings()``.
        self.endpoint_pinner = EndpointPinner()
        # The banner prints once even if several agent paths report anti-tamper;
        # later events still reach API consumers.
        self._anti_tamper_bannered = False
        # The --protocol selection: a name, a comma-joined string, a list/set or
        # None. With "telegram" selected, MTProto cloud keys and Secret-Chat E2E
        # keys share one keylog (both emitted as protocol="telegram").
        if active_protocol is None:
            _names = []
        elif isinstance(active_protocol, str):
            _names = [p.strip() for p in active_protocol.split(",") if p.strip()]
        else:
            _names = [str(p).strip() for p in active_protocol if str(p).strip()]
        self._active_protocols = set(_names)
        self._active_protocol = _names[0] if _names else None

    def set_filter(self, filter_engine) -> None:
        """Set a display filter engine. Only network-level fields are checked."""
        self._data_filter = filter_engine

    def install_display_filter(self, expression: str | None, logger) -> None:
        """Install a filter suitable for headless capture events."""
        if not expression:
            return
        try:
            from .filter.pipeline_filter import build_headless_filter

            engine = build_headless_filter(expression)
            if isinstance(engine, str):
                logger.warning("%s", engine)
                return
            self.set_filter(engine)
            logger.info("Display filter active: %s", expression)
        except Exception as exc:
            logger.warning("Invalid filter expression: %s", exc)

    def set_learned_offsets_sink(self, sink) -> None:
        """Forward ``plaintext_api_learned`` / ``module_offsets_learned`` payloads to *sink* (None disables)."""
        self._learned_offsets_sink = sink

    def route(self, payload: dict, data: bytes) -> None:
        """Parse an agent message payload and emit the corresponding event."""
        payload = _with_normalized_client_random(payload)
        self._routing.origin = _origin_of(payload)
        try:
            self._dispatch(payload, data)
        finally:
            self._routing.origin = None

    def _publish(self, event) -> None:
        """Emit *event* tagged with the routed payload's process origin (an origin already set wins)."""
        if event.process_origin is None:
            event.process_origin = getattr(self._routing, "origin", None)
        self._event_bus.emit(event)

    def _dispatch(self, payload: dict, data: bytes) -> None:
        """Emit the event for one normalized payload by its ``contentType``."""
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
        elif content_type in (ContentType.PLAINTEXT_API_LEARNED,
                              ContentType.MODULE_OFFSETS_LEARNED):
            self._record_learned_offsets(payload)

    def _record_learned_offsets(self, payload: dict) -> None:
        sink = self._learned_offsets_sink
        if sink is None:
            return
        # A cache failure must never break message routing for the capture.
        try:
            sink(payload)
        except Exception:  # noqa: BLE001
            self._logger.debug("learned offsets: recording failed", exc_info=True)

    def _emit_keylog(self, payload: dict) -> None:
        self._publish(KeylogEvent(
            key_data=payload["keylog"],
            protocol=payload_protocol(payload, "tls"),
        ))

    @staticmethod
    def _resolve_addresses(payload: dict) -> tuple:
        """Validated source/destination addresses and ports from the (untrusted) agent fields."""
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
        """The record's endpoints after pinning (unchanged for non-TCP or no client_random).

        Unpinned endpoints are synthetic only when the agent flags them (a QUIC
        tuple guessed before the peer was readable)."""
        (src_addr_str, src_port, dst_addr_str, dst_port,
         ss_family, src_addr, dst_addr) = self._resolve_addresses(payload)
        record = RecordEndpoints(src_addr_str, src_port, dst_addr_str, dst_port,
                                 src_addr, dst_addr, ss_family)
        resolved = self.endpoint_pinner.resolve(
            client_random, payload.get("transport", "tcp"),
            direction == DIRECTION_READ, record)
        return resolved if resolved is not None else ResolvedEndpoints(
            src_addr_str, src_port, dst_addr_str, dst_port, src_addr, dst_addr, ss_family,
            synthetic=payload.get("endpoints_synthetic") is True)

    @staticmethod
    def _endpoint_fields(endpoints: ResolvedEndpoints) -> dict:
        """DatalogEvent address fields (incl. the synthetic flag and observed_*)."""
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

        timestamp, received_at = held_capture_times(payload.get("held_ms"), time.time())
        self._publish(DatalogEvent(
            timestamp=timestamp,
            received_at=received_at,
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
            quic_midstream=payload.get("quic_midstream") is True,
            stream_offset=strict_int(payload.get("stream_offset")),
            fin=payload.get("fin") is True,
            library=str(payload.get("library") or ""),
            protocol=payload_protocol(payload, "tls"),
            **self._endpoint_fields(endpoints),
        ))

    def _emit_library_detected(self, payload: dict) -> None:
        self._publish(LibraryDetectedEvent(
            library=payload.get("library", ""),
            path=payload.get("path", ""),
            protocol=payload_protocol(payload, "tls"),
        ))

    def _emit_anti_tamper_detected(self, payload: dict) -> None:
        """Print one red anti-tamper banner (e.g. PairIP) and emit an event for API consumers."""
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
        self._publish(AntiTamperDetectedEvent(
            library=payload.get("library", ""),
            name=name,
            skipped_loader_hook=skipped,
        ))

    def _emit_console(self, payload: dict, level: str = "info") -> None:
        # Sinks print agent text verbatim: escape control sequences (ANSI/OSC injection).
        self._publish(ConsoleEvent(
            message=safe_terminal_text(payload.get("console", "")),
            level=level,
        ))

    def _emit_agent_dev_console(self, message: str) -> None:
        # Agent dev diagnostics (console_dev, devlog_*) are debug level with an
        # origin tag: they reach --debug-log and -d/-do only, never the normal
        # console, TUI log or non-debug JSONL. *message* must already be escaped.
        self._publish(ConsoleEvent(
            message=message,
            level="debug",
            origin=AGENT_DEV_ORIGIN,
        ))

    def _emit_console_dev(self, payload: dict) -> None:
        self._emit_agent_dev_console(
            safe_terminal_text(payload.get("console_dev", "")))

    def _emit_console_devlog(self, payload: dict, agent_level) -> None:
        # devlog_*() lines take the console_dev debug path. devlog_debug
        # (*agent_level* None) is unprefixed; info/warn/error carry the agent's
        # level and callsite so the real severity survives in the debug log.
        message = safe_terminal_text(str(payload.get("message", "")))
        if agent_level is not None:
            message = f"{format_devlog_prefix(agent_level, payload)} {message}"
        self._emit_agent_dev_console(message)

    def _emit_hook_breadcrumb(self, payload: dict) -> None:
        # Never printed: SSL_Logger keeps the last one so on_detach can name the
        # hook that was running if the target dies inside it.
        self._publish(HookBreadcrumbEvent(
            marker=payload.get("hook_breadcrumb", ""),
        ))

    def _emit_platform_report(self, payload: dict) -> None:
        # Forwarded as-is: SSL_Logger owns the log line and the --probe
        # acknowledgement, so the router carries no probe-mode policy.
        try:
            abi = int(payload.get("abi", 0) or 0)
        except (TypeError, ValueError):
            # A non-numeric ABI is still worth reporting; only the version is unknown.
            abi = 0
        self._publish(PlatformReportEvent(
            platform=safe_terminal_text(payload.get("platform", "")),
            target=safe_terminal_text(payload.get("target", "")),
            probe=bool(payload.get("probe", False)),
            abi=abi,
        ))

    def _emit_ssh_key(self, payload: dict) -> None:
        """Emit an SSH per-direction key/IV line (``SSH_ENC_KEY_C2S``, ``SSH_IV_S2C``, ...) as a KeylogEvent.

        This is raw derived key material for keys.log, not the Wireshark SSH
        dissector format; that comes from :meth:`_emit_ssh_keylog`.
        """
        key_type = payload.get("key_type", "")
        key_data = payload.get("key_data", "")
        if not key_type or not key_data:
            return
        line = f"{key_type} {key_data}"
        self._publish(KeylogEvent(
            key_data=line,
            protocol=payload_protocol(payload, "ssh"),
        ))

    def _emit_ssh_keylog(self, payload: dict) -> None:
        """Emit a SHARED_SECRET KeylogEvent for the Wireshark SSH dissector.

        The formatter renders ``<cookie> SHARED_SECRET <hex>``; Wireshark runs
        the RFC 4253 §7.2 KDF itself.
        """
        self._publish(KeylogEvent(
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

        Fields are forwarded verbatim (SPIs and keys are lowercase hex in
        on-wire order); the formatter renders one ``ikev2_decryption_table`` row.
        """
        keys = payload.get("keys") or {}
        self._publish(KeylogEvent(
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
        """Emit a structured CHILD_SA (ESP) KeylogEvent from the kernel ``add_sa`` keys.

        SPI and keys are lowercase hex in on-wire order (no byte-swap).
        """
        self._publish(KeylogEvent(
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

        Rendered as ``MTPROTO_AUTH_KEY <dc_id> <auth_key_id> <auth_key> <key_type>``.
        Under ``--protocol telegram`` the protocol is ``"telegram"`` (combined
        keylog with the E2E keys), else ``"mtproto"``.
        """
        protocol = "telegram" if "telegram" in self._active_protocols else "mtproto"
        auth_key = str(payload.get("auth_key", ""))
        auth_key_id = str(payload.get("auth_key_id", ""))
        # Datacenter::getAuthKey does not always fill the auth_key_id out-param;
        # the id is the low 64 bits of SHA1(auth_key), and the offline decryptor
        # looks keys up by it.
        if len(auth_key_id) != 16 and len(auth_key) == 512:
            try:
                import hashlib
                auth_key_id = hashlib.sha1(bytes.fromhex(auth_key)).digest()[-8:].hex()
            except ValueError:
                pass
        self._publish(KeylogEvent(
            protocol=protocol,
            payload={
                "auth_key_id": auth_key_id,
                "auth_key": auth_key,
                "dc_id": payload.get("dc_id", 0),
                "key_type": str(payload.get("key_type", "perm")),
            },
        ))

    def _emit_telegram_e2e_key(self, payload: dict) -> None:
        """Emit a Telegram Secret-Chat key as ``MTPROTO_E2E_KEY <key_fingerprint> <shared_key> <chat_id>``.

        Always ``protocol="telegram"``, in the same keylog as the MTProto cloud keys.
        """
        self._publish(KeylogEvent(
            protocol="telegram",
            payload={
                "shared_key": str(payload.get("shared_key", "")),
                "key_fingerprint": str(payload.get("key_fingerprint", "")),
                "chat_id": payload.get("chat_id", 0),
            },
        ))

    def _emit_private_key_material(self, payload: dict) -> None:
        """Emit a key-material KeylogEvent for a registry-driven protocol.

        ``classifier`` is the protocol name; the other payload fields are
        forwarded verbatim to that protocol's formatter.
        """
        classifier = str(payload.get("classifier", ""))
        if not classifier:
            return
        fields = {
            k: v for k, v in payload.items()
            if k not in ("contentType", "classifier", PROCESS_ORIGIN_KEY)
        }
        self._publish(KeylogEvent(protocol=classifier, payload=fields))

    def _emit_private_plaintext(self, payload: dict, data: bytes) -> None:
        """Emit decrypted plaintext as a DatalogEvent tagged with the payload's ``classifier``.

        Captured at a decrypt hook, so socket metadata is best-effort.
        """
        classifier = str(payload.get("classifier", ""))
        if not classifier:
            return
        src_addr_str, src_port, dst_addr_str, dst_port, ss_family, src_addr, dst_addr = self._resolve_addresses(payload)
        self._publish(DatalogEvent(
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
        """Emit Secret-Chat plaintext as a ``telegram_e2e`` DatalogEvent.

        Comes from the Java hooks (``SecretChatHelper.processDecryptedObject`` /
        ``performSendEncryptedRequest``), so socket metadata is best-effort.
        ``ssl_session_id`` gives each Secret-Chat id its own flow, as offline does.
        """
        src_addr_str, src_port, dst_addr_str, dst_port, ss_family, src_addr, dst_addr = self._resolve_addresses(payload)
        self._publish(DatalogEvent(
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
        self._publish(ConsoleEvent(message=msg, level="info"))

    def _emit_ohttp(self, payload: dict, data: bytes) -> None:
        self._publish(OhttpEvent(
            data=data,
            direction=payload.get("direction", ""),
            source=payload.get("source", ""),
            protocol=payload_protocol(payload, "ohttp"),
        ))

    def _filter_candidates(self, endpoints: ResolvedEndpoints, client_random: str,
                           direction: str) -> list:
        """The tuples a record may be filtered on: the emitted (pinned) one plus, under a synthetic pin, the real one.

        The real tuple is the record's ``observed`` one or one learned earlier.
        A record whose real tuple was never seen has only its 198.18/15 tuple,
        which host/port filters drop; protocol-only filters still pass it.
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
        """Emit a :class:`CallerStackEvent` per ``--attribute-sdk`` backtrace (once per connection).

        Frame strings are attacker-controlled: they only serve as lookup keys,
        and ``sdk`` holds the trusted ``{sdk, vendor, category}`` dict on a match
        (else ``None``). The frames travel escaped and capped under ``untrusted``.
        """
        java_frames, native_modules = caller_stack_lookup_keys(payload)
        sdk = self._classify_caller_stack(java_frames, native_modules)
        identity = self._caller_stack_identity(payload)
        self._log_caller_stack(identity["client_random"], payload, sdk)
        src_addr_str, src_port, dst_addr_str, dst_port, *_ = self._resolve_addresses(payload)
        self._publish(CallerStackEvent(
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
        """Optional connection/thread identity fields, coerced to event types (missing/invalid -> empty/0).

        ``thread_name`` and ``transport_module`` come from the target, so they are escaped and capped.
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
        self._publish(RequestContextEvent(
            event=event,
            protocol=payload_protocol(payload, "tls"),
            **request_context_fields(payload),
        ))

    def _emit_lifecycle(self, payload: dict) -> None:
        src_addr_str, src_port, dst_addr_str, dst_port, *_ = self._resolve_addresses(payload)
        # FlowCollector.on_data uses the same resolve_connection_key for
        # DatalogEvents, so lifecycle and data keys agree only if both pass the
        # same ``protocol`` (e.g. ``cr:quic:...``, not a ``tls`` key on one side).
        # The agent tags both message kinds alike; empty/None -> "tls" is also
        # enforced inside resolve_connection_key.
        protocol = payload_protocol(payload, "tls")
        client_random = payload.get("client_random", "")
        conn_id = resolve_connection_key(
            src_addr_str, src_port, dst_addr_str, dst_port,
            session_token=str(payload.get("ssl_session_id", "")),
            client_random=client_random,
            protocol=protocol,
        )

        # TLS handshake metadata (cipher_suite/protocol_version/server_name/alpn)
        # is offline-only, produced by offline/tshark.py from the full handshake.
        # The live SessionEvent carries identity + lifecycle and leaves those
        # fields at "" so live and offline metadata cannot drift.
        self._publish(SessionEvent(
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
