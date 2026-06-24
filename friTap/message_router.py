#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Message routing for friTap.

Extracted from SSL_Logger to reduce file length.
Routes agent message payloads to the EventBus as typed events.
"""

from __future__ import annotations
import logging

from .events import EventBus, KeylogEvent, DatalogEvent, LibraryDetectedEvent, AntiTamperDetectedEvent, ConsoleEvent, SessionEvent, OhttpEvent, HookBreadcrumbEvent
from .constants import SSL_READ, ContentType
from .connection_index import resolve_connection_key
from .ssl_logger import get_addr_string


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

    def __init__(self, event_bus: "EventBus", active_protocol: str | None = None) -> None:
        self._event_bus = event_bus
        self._logger = logging.getLogger("friTap.router")
        self._data_filter = None  # Optional FilterEngine for network-level filtering
        # Render the anti-tamper banner at most once per session, even though
        # several agent code paths may emit `anti_tamper_detected` (detection +
        # loader-hook skip). Subsequent events still flow to API consumers.
        self._anti_tamper_bannered = False
        # The user-selected --protocol. When it is "telegram", MTProto cloud keys
        # AND Secret-Chat E2E keys are routed into ONE combined keylog file (both
        # emitted as protocol="telegram"); otherwise behaviour is unchanged.
        self._active_protocol = active_protocol

    def set_filter(self, filter_engine) -> None:
        """Set a display filter engine. Only network-level fields are checked."""
        self._data_filter = filter_engine

    def route(self, payload: dict, data: bytes) -> None:
        """Parse an agent message payload and emit the corresponding event."""
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
        elif content_type == "hook_breadcrumb":
            self._emit_hook_breadcrumb(payload)

    def _emit_keylog(self, payload: dict) -> None:
        self._event_bus.emit(KeylogEvent(
            key_data=payload["keylog"],
            protocol=payload.get("protocol", "tls"),
        ))

    @staticmethod
    def _resolve_addresses(payload: dict) -> tuple:
        """Extract and normalize source/destination addresses from a payload."""
        src_addr = payload.get("src_addr", "")
        dst_addr = payload.get("dst_addr", "")
        ss_family = payload.get("ss_family", "AF_INET")
        return (
            get_addr_string(src_addr, ss_family),
            payload.get("src_port", 0),
            get_addr_string(dst_addr, ss_family),
            payload.get("dst_port", 0),
            ss_family,
            src_addr,  # raw
            dst_addr,  # raw
        )

    def _emit_datalog(self, payload: dict, data: bytes) -> None:
        src_addr_str, src_port, dst_addr_str, dst_port, ss_family, src_addr, dst_addr = self._resolve_addresses(payload)

        if self._data_filter is not None:
            if not self._check_data_filter(
                src_addr_str, src_port, dst_addr_str, dst_port,
                payload.get("protocol", "tls"),
            ):
                return

        function = payload.get("function", "")
        self._event_bus.emit(DatalogEvent(
            data=data,
            function=function,
            direction="read" if function in SSL_READ else "write",
            src_addr=src_addr_str,
            src_port=src_port,
            dst_addr=dst_addr_str,
            dst_port=dst_port,
            src_addr_raw=src_addr,
            dst_addr_raw=dst_addr,
            ss_family=ss_family,
            ssl_session_id=str(payload.get("ssl_session_id", "")),
            client_random=str(payload.get("client_random", "")),
            transport=payload.get("transport", "tcp"),
            http3_headers=payload.get("http3_headers"),
            stream_id=payload.get("stream_id"),
            quic_scid=str(payload.get("quic_scid", "")),
            quic_dcid=str(payload.get("quic_dcid", "")),
            quic_stream_type=str(payload.get("quic_stream_type", "")),
            protocol=payload.get("protocol", "tls"),
        ))

    def _emit_library_detected(self, payload: dict) -> None:
        self._event_bus.emit(LibraryDetectedEvent(
            library=payload.get("library", ""),
            path=payload.get("path", ""),
            protocol=payload.get("protocol", "tls"),
        ))

    def _emit_anti_tamper_detected(self, payload: dict) -> None:
        """Surface a detected anti-tamper runtime (e.g. PairIP). Renders ONE
        blank-line-padded red banner to the CLI (the single presentation point;
        the agent emits only the structured signal) and emits a structured event
        so API consumers (friTap/api.py) can react programmatically."""
        name = payload.get("name") or payload.get("library", "")
        note = payload.get("note", "")
        skipped = bool(payload.get("skippedLoaderHook", False))
        reason = payload.get("reason", "detected")
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
        self._event_bus.emit(ConsoleEvent(
            message=payload.get("console", ""),
            level=level,
        ))

    def _emit_console_dev(self, payload: dict) -> None:
        self._event_bus.emit(ConsoleEvent(
            message=payload.get("console_dev", ""),
            level="debug",
        ))

    def _emit_hook_breadcrumb(self, payload: dict) -> None:
        # In-memory crash-attribution marker (never printed). SSL_Logger stores
        # the last one so on_detach can name the hook that was executing if the
        # target dies inside it.
        self._event_bus.emit(HookBreadcrumbEvent(
            marker=payload.get("hook_breadcrumb", ""),
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
            protocol=payload.get("protocol", "ssh"),
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
        protocol = "telegram" if self._active_protocol == "telegram" else "mtproto"
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
            protocol=payload.get("protocol", "ohttp"),
        ))

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

    def _emit_lifecycle(self, payload: dict) -> None:
        src_addr_str, src_port, dst_addr_str, dst_port, *_ = self._resolve_addresses(payload)
        # connection_index.resolve_connection_key is the single source of truth
        # for connection keying. FlowCollector.on_data uses the very same helper
        # for DatalogEvents, so lifecycle keys and data keys agree by sharing
        # this function — there is no duplicated construction left to "keep in
        # sync". We MUST pass the same ``protocol`` both sites derive for a
        # connection (here from the payload, there from the event) so that, e.g.
        # a QUIC connection produces a ``cr:quic:...`` / ``sid:quic:...`` prefix
        # on BOTH paths instead of a mismatched ``tls`` prefix on one side.
        # The same coerced value also rides the emitted SessionEvent below; the
        # empty/None -> "tls" coercion is ALSO enforced inside
        # resolve_connection_key, so the two paths can never key differently.
        protocol = str(payload.get("protocol") or "tls")
        conn_id = resolve_connection_key(
            src_addr_str, src_port, dst_addr_str, dst_port,
            session_token=str(payload.get("ssl_session_id", "")),
            client_random=str(payload.get("client_random", "")),
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
            client_random=str(payload.get("client_random", "")),
            connection_id=conn_id,
            src_addr=src_addr_str,
            src_port=src_port,
            dst_addr=dst_addr_str,
            dst_port=dst_port,
            protocol=protocol,
        ))
