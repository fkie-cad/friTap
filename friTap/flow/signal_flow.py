"""Live Signal message decoding for :class:`FlowCollector` (``signal_messages``).

The host class owns the state; methods run under its lock unless noted.
Collector constants are read through ``_collector()`` at call time so patches take effect.
"""

import logging
from typing import Optional

from .collector_state import collector_module as _collector

# The collector's logger, so existing log filters and levels keep matching.
logger = logging.getLogger("friTap.flow.collector")


class SignalMessageFlowMixin:
    """Feeds Signal keys and per-direction stream bytes to the live decryptor."""

    def on_keylog(self, event) -> None:
        """EventBus subscriber for KeylogEvent: feed Signal keys to the live decryptor (no-op unless ``signal_messages``; TLS keylogs carry no ``payload`` and are ignored)."""
        if not self._signal_messages or self._signal_decryptor is None:
            return
        payload = getattr(event, 'payload', None)
        if not payload:
            return
        with self._lock:
            self._signal_decryptor.add_key(payload)

    def _collect_signal_messages(self, conn, direction, event, out_events) -> None:
        """Decode newly arrived live Signal messages for one DatalogEvent. Under lock.

        Re-runs the offline Signal pipeline over the per-direction buffer, adds new messages to the
        active flow's ``SignalLayer`` and stages a ``MessageEvent`` each in *out_events*. A key that
        arrives after its message's bytes is recovered offline, not here.
        """
        decryptor = self._signal_decryptor
        if decryptor is None or direction not in ("read", "write"):
            return
        data = getattr(event, 'data', b'') or b''
        if not data:
            return
        # Accumulate even before keys arrive so history is intact once they do.
        buf = self._extend_signal_buffer(conn, direction, data)
        if buf is None or not decryptor.has_keys:
            return

        # id(conn) disambiguates a reset connection (fresh state, empty buffer) reusing a conn_id, so dedup counters restart.
        stream_key = f"{conn.conn_id}:{direction}:{id(conn)}"
        new_msgs = decryptor.feed(
            stream_key, bytes(buf), direction,
            src_addr=getattr(event, 'src_addr', ''),
            src_port=getattr(event, 'src_port', 0),
            dst_addr=getattr(event, 'dst_addr', ''),
            dst_port=getattr(event, 'dst_port', 0),
            ss_family=getattr(event, 'ss_family', 'AF_INET'),
        )
        if not new_msgs:
            return

        flow = self._flows.get(conn.active_flow_id) if conn.active_flow_id else None
        if flow is not None:
            self._attach_signal_messages(flow, new_msgs)
        for msg in new_msgs:
            out_events.append(self._build_message_event(msg))

    @staticmethod
    def _extend_signal_buffer(conn, direction: str, data: bytes) -> Optional[bytearray]:
        """Append *data* to the live Signal buffer, or ``None`` once capped.

        Re-decrypting the whole stream per event makes an unbounded buffer a memory and O(n^2) CPU
        hazard, so past :data:`MAX_SIGNAL_RAW_BYTES` the buffer is released and decoding stops for that direction (logged once).
        """
        if direction in conn.signal_capped:
            return None
        buf = conn.signal_raw.setdefault(direction, bytearray())
        if len(buf) + len(data) > _collector().MAX_SIGNAL_RAW_BYTES:
            conn.signal_capped.add(direction)
            conn.signal_raw[direction] = bytearray()
            logger.warning(
                "Live Signal decoding stopped for %s (%s): stream exceeded %d bytes",
                conn.conn_id, direction, _collector().MAX_SIGNAL_RAW_BYTES)
            return None
        buf.extend(data)
        return buf

    def _attach_signal_messages(self, flow, msgs) -> None:
        """Append decrypted Signal messages onto *flow*'s SignalLayer; the dict must match offline ``_ingest_signal_message`` (:mod:`friTap.offline.signal.offline_decryptor`)."""

        from friTap.flow.layers import SignalLayer
        layer = flow.layer(SignalLayer.NAME)
        if not isinstance(layer, SignalLayer):
            layer = flow.add_layer(SignalLayer())
        if msgs and not getattr(layer, 'chat_type', ''):
            layer.chat_type = msgs[0].chat_type
            layer.identifier = msgs[0].identifier_hex
        for m in msgs:
            layer.messages.append({
                "sender": m.sender,
                "direction": m.direction,
                "timestamp": m.timestamp,
                "kind": m.kind,
                "body": m.body,
                "attachments": m.has_attachments,
                "quote": m.has_quote,
                "reaction": m.has_reaction,
            })
        layer.message_count = len(layer.messages)

    @staticmethod
    def _build_message_event(msg):
        """Build a MessageEvent from an offline-style DecryptedMessage."""
        from friTap.events import MessageEvent
        return MessageEvent(
            protocol="signal",
            direction=msg.direction,
            src_addr=msg.src_addr,
            src_port=msg.src_port,
            dst_addr=msg.dst_addr,
            dst_port=msg.dst_port,
            ss_family=msg.ss_family,
            chat_type=msg.chat_type,
            identifier=msg.identifier_hex,
            sender=msg.sender,
            kind=msg.kind,
            body=msg.body,
            timestamp=msg.timestamp,
            has_attachments=msg.has_attachments,
            has_quote=msg.has_quote,
            has_reaction=msg.has_reaction,
            raw=msg.message,
        )

    def _emit_message_events(self, events) -> None:
        """Emit staged MessageEvents on the bus. Must NOT hold _lock."""
        if not events or self._event_bus is None:
            return
        for ev in events:
            try:
                self._event_bus.emit(ev)
            except Exception:
                logger.debug("MessageEvent emit failed", exc_info=True)
