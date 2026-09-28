"""Shared test doubles for the offline (pcap -> .tap) decryptor tests.

* :func:`make_offline_entry` -- a minimal, never-invoked registry entry;
* :class:`FakeWriterState` -- a file-free ``_WriterState`` stand-in;
* :func:`patch_keylog_loaders` -- non-empty fake Telegram keylog loaders;
* :func:`cloud_msg` / :func:`e2e_msg` -- synthetic decrypted Telegram records
  on one client <-> DC connection.
"""

from __future__ import annotations

from friTap.flow.layers import AppLayer
from friTap.offline.mtproto.e2e.records import SecretChatMessage
from friTap.offline.mtproto.records import DecryptedMessage
from friTap.offline.registry import OfflineDecryptorEntry

TG_FINGERPRINT = "aabbccddeeff0011"
TG_BASE_TS = 1_700_000_000.0


def _noop_emitter(**_kwargs):  # pragma: no cover - never invoked
    return None


def make_offline_entry(name: str, **overrides) -> OfflineDecryptorEntry:
    """A minimal entry for *name*; any field can be replaced via *overrides*."""
    fields = dict(
        protocol_name=name,
        cli_flag=f"--{name}-keylog",
        cli_dest=f"{name}_keylog",
        requires_tls_strip=False,
        emitter=_noop_emitter,
        layer_cls=AppLayer,
        counter_prefix=name,
    )
    fields.update(overrides)
    return OfflineDecryptorEntry(**fields)


class FakeWriterState:
    """Minimal ``_WriterState`` stand-in (no TapWriter, no file I/O)."""

    def __init__(self) -> None:
        self.mtproto_meta: dict = {}
        self.telegram_e2e_meta: dict = {}

    def ensure_open(self, capture_start: float = 0.0) -> None:
        pass


def patch_keylog_loaders(monkeypatch) -> None:
    """Fake the three Telegram keylog loaders with non-empty cloud/E2E keymaps.

    The keymap values are opaque; the emitter only needs them non-empty to get
    past its "no usable keys" guard.
    """
    monkeypatch.setattr("friTap.offline.mtproto.keylog.load_mtproto_keylog",
                        lambda path: {b"\x11" * 8: object()})
    monkeypatch.setattr("friTap.offline.mtproto.keylog.load_mtproto_obf_keylog",
                        lambda path: [])
    monkeypatch.setattr("friTap.offline.mtproto.e2e.keylog.load_secret_chat_keylog",
                        lambda path: {b"\xaa" * 8: object()})


def _endpoints(direction: str) -> dict:
    client = ("10.0.0.1", 12345)
    server = ("149.154.167.51", 443)
    src, dst = (client, server) if direction == "write" else (server, client)
    return dict(src_addr=src[0], src_port=src[1], dst_addr=dst[0], dst_port=dst[1],
                ss_family="AF_INET")


def cloud_msg(i: int, direction: str, data: bytes) -> DecryptedMessage:
    """Cloud record *i* (msg_id ``100 + i``, timestamp ``TG_BASE_TS + i``)."""
    return DecryptedMessage(
        direction=direction, message=data, dc_id=2, transport="abridged",
        obfuscated=True, auth_key_id_hex="1122334455667788", msg_id=100 + i,
        timestamp=TG_BASE_TS + i, **_endpoints(direction),
    )


def e2e_msg(i: int, direction: str, data: bytes) -> SecretChatMessage:
    """Secret-Chat record *i* in chat 4242 (timestamp ``TG_BASE_TS + i``)."""
    return SecretChatMessage(
        message=data, chat_id=4242, key_fingerprint_hex=TG_FINGERPRINT,
        msg_key_hex=f"{i:032x}", direction=direction, timestamp=TG_BASE_TS + i,
        **_endpoints(direction),
    )
