"""Offline Telegram secret-chat (end-to-end) decryption support.

Secret chats ride on top of the cloud-chat transport decryptor: each E2E message
is a TL-serialized blob inside an already-decrypted transport message
(:class:`friTap.offline.mtproto.records.DecryptedMessage`). This subpackage adds
the second AES-IGE layer, keyed by the per-chat 256-byte shared key rather than
the transport auth_key, and reuses the MTProto 2.0 KDF/IGE primitives in
:mod:`friTap.offline.mtproto.crypto`. Errors use the parent package's hierarchy.
"""
