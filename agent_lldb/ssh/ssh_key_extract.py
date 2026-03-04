#!/usr/bin/env python3
"""
LLDB script for SSH key extraction from OpenSSH.

Usage:
    lldb -p <sshd_pid> -o "command script import ssh_key_extract.py"

Sets breakpoints on kex_derive_keys() and ssh_set_newkeys(),
then reads the sshenc struct to extract cipher keys and IVs.

Based on keys-in-flux research:
https://github.com/fkie-cad/keys-in-flux-paper-material
"""

import os
import struct

try:
    import lldb
except ImportError:
    print("ERROR: This script must be run inside LLDB.")
    print("Usage: lldb -p <sshd_pid> -o 'command script import ssh_key_extract.py'")
    raise

# Output file for extracted keys
KEYLOG_FILE = os.environ.get("SSH_KEYLOG_FILE", "ssh_keys.log")

# sshenc struct offsets (OpenSSH 9.x / 10.x)
SSHENC_CIPHER_NAME_OFFSET = 0
SSHENC_KEY_LEN_OFFSET = 20
SSHENC_IV_LEN_OFFSET = 24
SSHENC_KEY_PTR_OFFSET = 32

# Target functions
TARGET_FUNCTIONS = [
    "kex_derive_keys",
    "ssh_set_newkeys",
]


def read_pointer(process, addr):
    """Read a pointer-sized value from process memory."""
    ptr_size = process.GetAddressByteSize()
    error = lldb.SBError()
    data = process.ReadMemory(addr, ptr_size, error)
    if error.Fail():
        raise RuntimeError(f"Pointer read failed at 0x{addr:x}: {error.GetCString()}")
    fmt = "<Q" if ptr_size == 8 else "<I"
    return struct.unpack(fmt, data)[0]


def read_uint32(process, addr):
    """Read a 32-bit unsigned integer."""
    error = lldb.SBError()
    data = process.ReadMemory(addr, 4, error)
    if error.Fail():
        raise RuntimeError(f"uint32 read failed at 0x{addr:x}: {error.GetCString()}")
    return struct.unpack("<I", data)[0]


def read_string(process, addr, max_len=128):
    """Read a null-terminated C string."""
    error = lldb.SBError()
    data = process.ReadMemory(addr, max_len, error)
    if error.Fail():
        raise RuntimeError(f"String read failed at 0x{addr:x}: {error.GetCString()}")
    null_idx = data.find(b'\x00')
    if null_idx >= 0:
        data = data[:null_idx]
    return data.decode('utf-8', errors='replace')


def read_bytes(process, addr, length):
    """Read raw bytes from process memory."""
    error = lldb.SBError()
    data = process.ReadMemory(addr, length, error)
    if error.Fail():
        raise RuntimeError(f"Memory read failed at 0x{addr:x}: {error.GetCString()}")
    return data


def extract_sshenc_keys(process, sshenc_addr, direction):
    """Read cipher name, key, and IV from an sshenc struct."""
    results = []
    try:
        cipher_name_ptr = read_pointer(process, sshenc_addr + SSHENC_CIPHER_NAME_OFFSET)
        cipher_name = read_string(process, cipher_name_ptr, 64)
        key_len = read_uint32(process, sshenc_addr + SSHENC_KEY_LEN_OFFSET)
        iv_len = read_uint32(process, sshenc_addr + SSHENC_IV_LEN_OFFSET)
        ptr_size = process.GetAddressByteSize()
        key_ptr = read_pointer(process, sshenc_addr + SSHENC_KEY_PTR_OFFSET)
        iv_ptr = read_pointer(process, sshenc_addr + SSHENC_KEY_PTR_OFFSET + ptr_size)

        if 0 < key_len < 256 and key_ptr != 0:
            key_data = read_bytes(process, key_ptr, key_len)
            line = f"SSH_ENC_KEY_{direction.upper()} {key_data.hex()}"
            results.append(line)
            print(f"[SSH] {direction} key: cipher={cipher_name}, len={key_len}")

        if 0 < iv_len < 256 and iv_ptr != 0:
            iv_data = read_bytes(process, iv_ptr, iv_len)
            line = f"SSH_IV_{direction.upper()} {iv_data.hex()}"
            results.append(line)
            print(f"[SSH] {direction} IV: cipher={cipher_name}, len={iv_len}")

    except Exception as e:
        print(f"[SSH] Error reading sshenc at 0x{sshenc_addr:x}: {e}")

    return results


def set_breakpoints(debugger, target):
    """Set breakpoints on SSH key derivation functions."""
    for fn in TARGET_FUNCTIONS:
        bp = target.BreakpointCreateByName(fn)
        if bp.IsValid():
            print(f"[SSH] Breakpoint set on {fn}")
        else:
            print(f"[SSH] {fn} not found")


def __lldb_init_module(debugger, internal_dict):
    """Entry point when imported via LLDB command script import."""
    print("=" * 60)
    print("friTap SSH Key Extractor (LLDB)")
    print(f"Writing keys to: {KEYLOG_FILE}")
    print("=" * 60)

    target = debugger.GetSelectedTarget()
    if not target.IsValid():
        print("[SSH] No valid target. Attach to a process first.")
        return

    set_breakpoints(debugger, target)
    print("[SSH] Breakpoints set. Continue execution to capture keys.")
