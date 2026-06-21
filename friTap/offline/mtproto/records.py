"""Dataclasses for offline MTProto decryption results and run statistics."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class DecryptedMessage:
    """One successfully decrypted MTProto record (its TL payload)."""

    src_addr: str
    src_port: int
    dst_addr: str
    dst_port: int
    ss_family: str  # "AF_INET" | "AF_INET6"
    direction: str  # "read" (server->client) | "write" (client->server)
    message: bytes  # the TL-serialized payload
    dc_id: int
    transport: str  # "abridged" | "intermediate" | ...
    obfuscated: bool
    auth_key_id_hex: str


@dataclass
class MtprotoStats:
    """Counters for one ``iter_decrypted_messages`` run."""

    streams: int = 0
    messages: int = 0
    records_undecryptable: int = 0
    streams_degraded: int = 0

    def add_stream(self) -> None:
        self.streams += 1

    def add_message(self) -> None:
        self.messages += 1

    def add_undecryptable(self) -> None:
        self.records_undecryptable += 1

    def add_degraded(self) -> None:
        self.streams_degraded += 1
