#!/usr/bin/env python3

"""Conversation siblings: the flows that make up one logical chat conversation.

A plain mixin (no BINDINGS/CSS/compose); the host screen supplies ``_replay_ctrl``
and the ``_live_flow_collector`` hook. Signal groups by chat-server endpoint,
Telegram Secret Chats by the shared chat-key session id, MTProto cloud chats by
conversation key. No capture/wizard code.
"""

from __future__ import annotations


class ConversationSiblingsMixin:
    """Per-protocol conversation-sibling lookup (host: a Textual ``Screen``)."""
    @staticmethod
    def _signal_server_endpoint(flow):
        """The (addr, port) of the service side: the lower port (e.g. 443)."""
        if flow.src_port <= flow.dst_port:
            return (flow.src_addr, flow.src_port)
        return (flow.dst_addr, flow.dst_port)

    def _signal_conversation_siblings(self, flow) -> list:
        """Signal flows of this session sharing the same chat-server endpoint.

        One conversation spans several TCP connections to the same chat server, and one
        websocket multiplexes all conversations, so the service endpoint alone reunites
        them. chat_type is not part of the key (one connection carries 1:1 and group messages).
        """
        if getattr(flow, "transport", "") != "signal":
            return []
        key = self._signal_server_endpoint(flow)

        def matches(candidate) -> bool:
            return (getattr(candidate, "transport", "") == "signal"
                    and self._signal_server_endpoint(candidate) == key)

        # Replay matches the cheap in-memory summaries and loads only hits as full Flows
        # (on-demand, LRU-cached), so detail-open never decodes every flow; live mode filters the collector's flows.
        return self._sibling_flows_matching(matches)

    def _telegram_e2e_conversation_siblings(self, flow) -> list:
        """Secret-Chat flows sharing *flow*'s chat key (``ssl_session_id`` ``telegram_e2e:<fingerprint>``).

        One Secret Chat spans several flows; reuniting them gives one deduped, ordered transcript.
        """
        if getattr(flow, "transport", "") != "telegram_e2e":
            return []
        session_id = getattr(flow, "ssl_session_id", "") or ""
        if not session_id:
            return []

        def matches(candidate) -> bool:
            return (getattr(candidate, "transport", "") == "telegram_e2e"
                    and getattr(candidate, "ssl_session_id", "") == session_id)

        return self._sibling_flows_matching(matches)

    def _sibling_flows_matching(self, matches) -> list:
        """Full Flows whose summary (replay, loaded on demand, LRU-cached) or live flow satisfies *matches*."""
        if self._replay_ctrl is not None:
            sibling_ids = [s.flow_id for s in self._replay_ctrl.get_summaries()
                           if matches(s)]
            siblings = [self._replay_ctrl.get_flow(fid) for fid in sibling_ids]
            return [f for f in siblings if f is not None]
        collector = self._live_flow_collector()
        flows = collector.get_flows() if collector else []
        return [f for f in flows if matches(f)]

    def _mtproto_conversation_siblings(self, flow) -> list:
        """Cloud-chat flows carrying text for the same peer as *flow*.

        Every MTProto packet is its own flow: candidates are pre-filtered on the cheap
        Method scalar, loaded, and kept when a chat-text entry shares a conversation key.
        """
        from friTap.flow import telegram_conversation as tconv
        if getattr(flow, "transport", "") != "mtproto":
            return []
        self_id = self._telegram_self_id(flow)
        keys = tconv.conversation_keys_of(flow, self_id)
        if not keys:
            return []

        def matches(candidate) -> bool:
            return (getattr(candidate, "transport", "") == "mtproto"
                    and tconv.flow_has_chat_text(candidate))

        return [f for f in self._sibling_flows_matching(matches)
                if tconv.conversation_keys_of(f, self_id) & keys]

    @staticmethod
    def _telegram_self_id(flow) -> int:
        """The capturing account's user id from *flow*'s structured users (0 if unknown)."""
        try:
            layer = flow.layer(getattr(flow, "transport", ""))
        except Exception:
            layer = None
        for user in getattr(layer, "users", None) or []:
            if isinstance(user, dict) and "self" in (user.get("flags") or []):
                return int(user.get("id") or 0)
        return 0

    def _conversation_siblings(self, flow) -> list:
        """Dispatch to the per-protocol conversation-sibling lookup."""
        if getattr(flow, "transport", "") == "telegram_e2e":
            return self._telegram_e2e_conversation_siblings(flow)
        if getattr(flow, "transport", "") == "mtproto":
            return self._mtproto_conversation_siblings(flow)
        return self._signal_conversation_siblings(flow)
