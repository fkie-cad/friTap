#!/usr/bin/env python3

"""
Shared protocol-selection flow for the friTap TUI.

Chains :class:`ProtocolSelectModal` into :class:`CustomCipherModal` so the
setup wizard and the ``p`` hotkey pick protocols the same way:

* ``custom`` ("Custom Encryption") -> cipher modal (required) -> the ciphers;
* ``auto``                        -> no cipher modal        -> ``["auto"]``;
* anything else                   -> cipher modal (optional) -> ``[proto] + ciphers``.

Esc in the cipher modal re-opens the protocol modal; Esc in the protocol modal
calls ``on_back``.
"""

from __future__ import annotations

from typing import Callable, List, Optional

OnDone = Callable[[str, List[str]], None]


def format_protocols(protocols: List[str]) -> str:
    """Human-readable protocol set, e.g. ``["tls", "rc4"]`` -> ``"TLS+RC4"``."""
    return "+".join(protocols).upper()


def combine_protocols(
    protocol: str, ciphers: List[str], cipher_names: Optional[List[str]] = None
) -> List[str]:
    """Ordered, de-duplicated protocol list: the main protocol first, then ciphers.

    *cipher_names* (all custom-cipher names) is forwarded to
    :func:`order_protocol_selection` to avoid re-querying the registry."""
    from friTap.protocols.registry import CUSTOM_GROUP, order_protocol_selection

    head = [] if protocol == CUSTOM_GROUP else [protocol]
    return order_protocol_selection(head + list(ciphers), cipher_names)


def apply_protocol_selection(state, protocols: List[str]) -> None:
    """Store a protocol selection on the TUI state: ``state.protocols`` is the
    full ordered set, ``state.protocol`` its primary (first) element."""
    state.protocol = protocols[0]
    state.protocols = protocols


def select_protocols(
    app,
    on_done: OnDone,
    on_back: Optional[Callable[[], None]] = None,
    registry=None,
) -> None:
    """Run the protocol -> custom-cipher modal chain and report the selection.

    ``on_done(primary, protocols)`` receives the primary protocol (the first
    element, used for the wizard's branching) and the full ordered list.
    """
    from friTap.protocols.registry import CUSTOM_GROUP

    from .modals.custom_cipher_modal import CustomCipherModal, available_custom_ciphers
    from .modals.protocol_modal import ProtocolSelectModal

    # Computed once and shared by both modals (instantiates every handler).
    ciphers = available_custom_ciphers()
    cipher_names = [entry.name for entry in ciphers]

    def _open_protocol_modal() -> None:
        app.push_screen(
            ProtocolSelectModal(registry=registry, ciphers=ciphers), callback=_on_protocol
        )

    def _finish(protocols: List[str]) -> None:
        on_done(protocols[0], protocols)

    def _on_protocol(protocol: Optional[str]) -> None:
        if protocol is None:
            if on_back is not None:
                on_back()
            return
        if protocol == "auto":
            _finish(["auto"])
            return
        if not ciphers:
            _finish([protocol])
            return
        _open_cipher_modal(protocol)

    def _open_cipher_modal(protocol: str) -> None:
        def _on_ciphers(selected: Optional[List[str]]) -> None:
            if selected is None:
                _open_protocol_modal()
                return
            _finish(combine_protocols(protocol, selected, cipher_names))

        app.push_screen(
            CustomCipherModal(required=protocol == CUSTOM_GROUP, ciphers=ciphers),
            callback=_on_ciphers,
        )

    _open_protocol_modal()
