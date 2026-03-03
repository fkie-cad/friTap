#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SSH key extractor using LLDB breakpoints.

Translated from keys-in-flux openssh_kex_lldb.py approach.
Sets breakpoints on kex_derive_keys() and ssh_set_newkeys(),
then reads the sshenc struct on return to extract cipher keys and IVs.

Usage:
    Automatically loaded by SSL_Logger when backend is LLDB/GDB
    and protocol is SSH.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger("friTap.protocols.ssh_extractor")


# sshenc struct offsets (OpenSSH 9.x / 10.x)
SSHENC_CIPHER_NAME_OFFSET = 0
SSHENC_KEY_LEN_OFFSET = 20
SSHENC_IV_LEN_OFFSET = 24
SSHENC_KEY_PTR_OFFSET = 32


class SSHKeyExtractor:
    """Extract SSH encryption keys via LLDB/GDB breakpoints.

    Targets OpenSSH's ``kex_derive_keys()`` and ``ssh_set_newkeys()``
    functions to capture per-direction encryption keys and IVs from
    the ``sshenc`` struct.
    """

    # Target functions for breakpoint placement
    TARGET_FUNCTIONS = [
        "kex_derive_keys",
        "ssh_set_newkeys",
    ]

    def __init__(self, backend: Any, event_bus: Any) -> None:
        self._backend = backend
        self._event_bus = event_bus
        self._extracted_keys: list[dict] = []

    @property
    def extracted_keys(self) -> list[dict]:
        """Return all extracted key records."""
        return list(self._extracted_keys)

    def attach(self, process: Any) -> None:
        """Set breakpoints on SSH key derivation functions.

        Parameters
        ----------
        process
            Backend-specific process handle (LLDB SBProcess or GDB inferior).
        """
        backend_name = self._backend.name

        if backend_name == "lldb":
            self._attach_lldb(process)
        elif backend_name == "gdb":
            self._attach_gdb(process)
        else:
            logger.warning("SSH extractor: unsupported backend '%s'", backend_name)

    def _attach_lldb(self, process: Any) -> None:
        """Set LLDB breakpoints on SSH functions."""
        try:
            target = process.GetTarget()
            for fn in self.TARGET_FUNCTIONS:
                bp = target.BreakpointCreateByName(fn)
                if bp.IsValid():
                    logger.info("SSH extractor: breakpoint set on %s", fn)
                else:
                    logger.debug("SSH extractor: %s not found", fn)
        except Exception as e:
            logger.error("SSH extractor LLDB attach error: %s", e)

    def _attach_gdb(self, process: Any) -> None:
        """Set GDB breakpoints on SSH functions."""
        try:
            for fn in self.TARGET_FUNCTIONS:
                try:
                    import gdb
                    gdb.Breakpoint(fn)
                    logger.info("SSH extractor: breakpoint set on %s", fn)
                except Exception:
                    logger.debug("SSH extractor: %s not found", fn)
        except ImportError:
            logger.warning("SSH extractor: gdb module not available")

    def read_sshenc_keys(self, process: Any, sshenc_addr: int, direction: str) -> Optional[dict]:
        """Read encryption keys and IVs from an sshenc struct.

        Parameters
        ----------
        process
            Backend process handle for memory reads.
        sshenc_addr
            Address of the sshenc struct in target memory.
        direction
            "client" or "server".

        Returns
        -------
        dict or None
            Key record with cipher, key_data, iv_data, etc.
        """
        try:
            backend = self._backend

            # Read cipher name pointer and dereference
            cipher_name_ptr = backend.read_pointer(process, sshenc_addr + SSHENC_CIPHER_NAME_OFFSET)
            cipher_name = backend.read_string(process, cipher_name_ptr, 64)

            key_len = backend.read_uint32(process, sshenc_addr + SSHENC_KEY_LEN_OFFSET)
            iv_len = backend.read_uint32(process, sshenc_addr + SSHENC_IV_LEN_OFFSET)

            ptr_size = process.GetAddressByteSize() if hasattr(process, 'GetAddressByteSize') else 8

            key_ptr = backend.read_pointer(process, sshenc_addr + SSHENC_KEY_PTR_OFFSET)
            iv_ptr = backend.read_pointer(process, sshenc_addr + SSHENC_KEY_PTR_OFFSET + ptr_size)

            record = {
                "direction": direction,
                "cipher": cipher_name,
                "key_len": key_len,
                "iv_len": iv_len,
            }

            if 0 < key_len < 256 and key_ptr != 0:
                key_data = backend.read_memory(process, key_ptr, key_len)
                record["key_data"] = key_data.hex()
                logger.info("SSH %s key: cipher=%s, len=%d", direction, cipher_name, key_len)

            if 0 < iv_len < 256 and iv_ptr != 0:
                iv_data = backend.read_memory(process, iv_ptr, iv_len)
                record["iv_data"] = iv_data.hex()
                logger.info("SSH %s IV: cipher=%s, len=%d", direction, cipher_name, iv_len)

            self._extracted_keys.append(record)

            # Emit event if event bus is available
            if self._event_bus:
                from ..events import KeylogEvent
                key_line = f"SSH_ENC_KEY_{direction.upper()} {record.get('key_data', '')}"
                self._event_bus.emit(KeylogEvent(key_data=key_line))

            return record

        except Exception as e:
            logger.error("SSH extractor: error reading sshenc at 0x%x: %s", sshenc_addr, e)
            return None

    def format_keylog(self) -> str:
        """Format all extracted keys as a keylog string."""
        lines = []
        for record in self._extracted_keys:
            direction = record.get("direction", "unknown")
            if "key_data" in record:
                lines.append(f"SSH_ENC_KEY_{direction.upper()} {record['key_data']}")
            if "iv_data" in record:
                lines.append(f"SSH_IV_{direction.upper()} {record['iv_data']}")
        return "\n".join(lines)
