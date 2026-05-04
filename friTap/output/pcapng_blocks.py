"""Shared PCAPNG block types, constants, and helpers.

Used by PcapngSink, PcapngOutputHandler, and LiveAutoDecryptHandler
to avoid duplicating block-level encoding logic.
"""

import struct

# PCAPNG block types
BT_SHB = 0x0A0D0D0A   # Section Header Block
BT_IDB = 0x00000001   # Interface Description Block
BT_EPB = 0x00000006   # Enhanced Packet Block
BT_DSB = 0x0000000A   # Decryption Secrets Block

# Secrets types
TLS_KEY_LOG = 0x544C534B   # "TLSK" - TLS Key Log

# Link types
LINKTYPE_RAW = 101
LINKTYPE_ETHERNET = 1

# Flush to disk every N Enhanced Packet Blocks
EPB_FLUSH_INTERVAL = 32


def pad4(n: int) -> int:
    """Round up to next multiple of 4."""
    return (n + 3) & ~3


def build_block(block_type: int, body: bytes) -> bytes:
    """Build a complete PCAPNG block with padding and trailing length."""
    padded_len = pad4(len(body))
    block_len = 12 + padded_len
    padding = b"\x00" * (padded_len - len(body))
    return struct.pack("<II", block_type, block_len) + body + padding + struct.pack("<I", block_len)


def build_shb() -> bytes:
    """Build a Section Header Block."""
    body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    block_len = 12 + len(body)
    return struct.pack("<II", BT_SHB, block_len) + body + struct.pack("<I", block_len)


def build_idb(link_type: int = LINKTYPE_RAW, snap_len: int = 65535) -> bytes:
    """Build an Interface Description Block."""
    body = struct.pack("<HHI", link_type, 0, snap_len)
    return build_block(BT_IDB, body)


def build_dsb(secrets_data: bytes) -> bytes:
    """Build a Decryption Secrets Block from raw secrets bytes."""
    body = struct.pack("<II", TLS_KEY_LOG, len(secrets_data)) + secrets_data
    return build_block(BT_DSB, body)


def build_epb(packet: bytes, timestamp_us: int) -> bytes:
    """Build an Enhanced Packet Block."""
    ts_high = (timestamp_us >> 32) & 0xFFFFFFFF
    ts_low = timestamp_us & 0xFFFFFFFF
    captured_len = len(packet)
    body = struct.pack("<IIIII", 0, ts_high, ts_low, captured_len, captured_len) + packet
    return build_block(BT_EPB, body)
