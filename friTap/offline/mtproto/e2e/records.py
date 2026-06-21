"""Dataclasses for offline secret-chat (E2E) decryption results and run statistics."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SecretChatMessage:
    """One successfully decrypted secret-chat E2E message (its TL payload)."""

    src_addr: str
    src_port: int
    dst_addr: str
    dst_port: int
    ss_family: str  # "AF_INET" | "AF_INET6"
    direction: str  # "read" (server->client) | "write" (client->server)
    message: bytes  # the TL-serialized payload
    chat_id: int
    key_fingerprint_hex: str
    origin: str = "decrypted"  # "decrypted" | "plaintext_hook"


@dataclass
class SecretChatStats:
    """Counters for one ``iter_secret_chat_messages`` run."""

    messages: int = 0
    blobs_seen: int = 0
    records_undecryptable: int = 0

    def add_message(self) -> None:
        self.messages += 1

    def add_blob(self) -> None:
        self.blobs_seen += 1

    def add_undecryptable(self) -> None:
        self.records_undecryptable += 1
