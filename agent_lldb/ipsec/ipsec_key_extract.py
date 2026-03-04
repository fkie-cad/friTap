#!/usr/bin/env python3
"""
LLDB script for IPSec key extraction from strongSwan charon.

Usage:
    lldb -p <charon_pid> -o "command script import ipsec_key_extract.py"

Sets breakpoints on ikev2_derive_child_sa_keys() and derive_ike_keys()
to extract ESP and IKE SA key material.

Based on keys-in-flux research:
https://github.com/fkie-cad/keys-in-flux-paper-material
"""

import os
import struct

try:
    import lldb
except ImportError:
    print("ERROR: This script must be run inside LLDB.")
    print("Usage: lldb -p <charon_pid> -o 'command script import ipsec_key_extract.py'")
    raise

# Output file for extracted keys
KEYLOG_FILE = os.environ.get("IPSEC_KEYLOG_FILE", "ipsec_keys.log")

# IKE SA key labels
IKE_KEY_LABELS = ["SK_ai", "SK_ar", "SK_ei", "SK_er", "SK_pi", "SK_pr"]

# Child SA key labels
CHILD_KEY_LABELS = ["encr_i", "encr_r", "integ_i", "integ_r"]

# Target functions
TARGET_FUNCTIONS = [
    "ikev2_derive_child_sa_keys",
    "derive_ike_keys",
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


def read_bytes(process, addr, length):
    """Read raw bytes from process memory."""
    error = lldb.SBError()
    data = process.ReadMemory(addr, length, error)
    if error.Fail():
        raise RuntimeError(f"Memory read failed at 0x{addr:x}: {error.GetCString()}")
    return data


def read_key_material(process, ptr_addr, label):
    """Read a strongSwan key_material_t struct: { void *ptr, size_t len }."""
    try:
        data_ptr = read_pointer(process, ptr_addr)
        ptr_size = process.GetAddressByteSize()
        data_len = read_pointer(process, ptr_addr + ptr_size)

        if 0 < data_len < 1024 and data_ptr != 0:
            data = read_bytes(process, data_ptr, data_len)
            hex_str = data.hex()
            print(f"[IPSec] {label}: {data_len} bytes")
            return hex_str
    except Exception as e:
        print(f"[IPSec] Error reading {label} at 0x{ptr_addr:x}: {e}")
    return None


def set_breakpoints(debugger, target):
    """Set breakpoints on IPSec key derivation functions."""
    for fn in TARGET_FUNCTIONS:
        bp = target.BreakpointCreateByName(fn)
        if bp.IsValid():
            print(f"[IPSec] Breakpoint set on {fn}")
        else:
            print(f"[IPSec] {fn} not found")


def __lldb_init_module(debugger, internal_dict):
    """Entry point when imported via LLDB command script import."""
    print("=" * 60)
    print("friTap IPSec Key Extractor (LLDB) -- strongSwan")
    print(f"Writing keys to: {KEYLOG_FILE}")
    print("=" * 60)

    target = debugger.GetSelectedTarget()
    if not target.IsValid():
        print("[IPSec] No valid target. Attach to a process first.")
        return

    set_breakpoints(debugger, target)
    print("[IPSec] Breakpoints set. Continue execution to capture keys.")
