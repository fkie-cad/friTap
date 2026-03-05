#!/usr/bin/env python3
"""
Standalone GDB script for IPSec key extraction from strongSwan charon.

Usage:
    gdb -x ipsec_key_extract.py -p <charon_pid>
    gdb -batch -x ipsec_key_extract.py -p <charon_pid>

Sets breakpoints on ikev2_derive_child_sa_keys() and derive_ike_keys()
to extract ESP and IKE SA key material.

Based on keys-in-flux research:
https://github.com/fkie-cad/keys-in-flux-paper-material
"""

import sys
import struct
import os

try:
    import gdb
except ImportError:
    print("ERROR: This script must be run inside GDB.")
    print("Usage: gdb -x ipsec_key_extract.py -p <charon_pid>")
    sys.exit(1)

# Output file for extracted keys
KEYLOG_FILE = os.environ.get("IPSEC_KEYLOG_FILE", "ipsec_keys.log")

# IKE SA key labels
IKE_KEY_LABELS = ["SK_ai", "SK_ar", "SK_ei", "SK_er", "SK_pi", "SK_pr"]

# Child SA key labels
CHILD_KEY_LABELS = ["encr_i", "encr_r", "integ_i", "integ_r"]


def get_pointer_size():
    """Detect pointer size from GDB architecture."""
    try:
        arch = gdb.selected_frame().architecture().name()
        if "i386" in arch or ("arm" in arch and "aarch64" not in arch):
            return 4
    except Exception:
        pass
    return 8


def read_pointer(addr):
    """Read a pointer from inferior memory."""
    inferior = gdb.selected_inferior()
    ptr_size = get_pointer_size()
    data = inferior.read_memory(addr, ptr_size).tobytes()
    fmt = "<Q" if ptr_size == 8 else "<I"
    return struct.unpack(fmt, data)[0]


def read_bytes(addr, length):
    """Read raw bytes from inferior memory."""
    inferior = gdb.selected_inferior()
    return inferior.read_memory(addr, length).tobytes()


def read_key_material(ptr_addr, label):
    """Read a strongSwan key_material_t struct: { void *ptr, size_t len }."""
    try:
        data_ptr = read_pointer(ptr_addr)
        ptr_size = get_pointer_size()
        data_len = read_pointer(ptr_addr + ptr_size)  # size_t

        if data_len > 0 and data_len < 1024 and data_ptr != 0:
            data = read_bytes(data_ptr, data_len)
            hex_str = data.hex()
            print(f"[IPSec] {label}: {data_len} bytes")
            return hex_str
    except Exception as e:
        print(f"[IPSec] Error reading {label} at 0x{ptr_addr:x}: {e}")
    return None


class DeriveChildSaKeysBreakpoint(gdb.Breakpoint):
    """Breakpoint on ikev2_derive_child_sa_keys() for ESP keys."""

    def __init__(self):
        super().__init__("ikev2_derive_child_sa_keys", gdb.BP_BREAKPOINT)
        print("[IPSec] Breakpoint set on ikev2_derive_child_sa_keys")

    def stop(self):
        try:
            # Capture argument registers (x86-64 calling convention)
            regs = ["$rdi", "$rsi", "$rdx", "$rcx", "$r8", "$r9"]
            arg_addrs = []
            for reg in regs[:8]:
                try:
                    arg_addrs.append(int(gdb.parse_and_eval(reg)))
                except Exception:
                    arg_addrs.append(0)

            print("[IPSec] ikev2_derive_child_sa_keys hit")

            # Finish to get output values
            gdb.execute("finish")

            # Read output key material (args 4-7 are output pointers)
            lines = []
            for i, label in enumerate(CHILD_KEY_LABELS):
                if i + 4 < len(arg_addrs) and arg_addrs[i + 4] != 0:
                    key_hex = read_key_material(arg_addrs[i + 4], label)
                    if key_hex:
                        line = f"IPSEC_{label.upper()} {key_hex}"
                        lines.append(line)

            if lines:
                with open(KEYLOG_FILE, "a") as f:
                    for line in lines:
                        f.write(line + "\n")
                print(f"[IPSec] Extracted {len(lines)} Child SA keys")

        except Exception as e:
            print(f"[IPSec] Error in ikev2_derive_child_sa_keys: {e}")

        return False


class DeriveIkeKeysBreakpoint(gdb.Breakpoint):
    """Breakpoint on derive_ike_keys() for IKE SA keys."""

    def __init__(self):
        super().__init__("derive_ike_keys", gdb.BP_BREAKPOINT)
        print("[IPSec] Breakpoint set on derive_ike_keys")

    def stop(self):
        try:
            regs = ["$rdi", "$rsi", "$rdx", "$rcx", "$r8", "$r9"]
            arg_addrs = []
            for reg in regs:
                try:
                    arg_addrs.append(int(gdb.parse_and_eval(reg)))
                except Exception:
                    arg_addrs.append(0)

            print("[IPSec] derive_ike_keys hit")
            gdb.execute("finish")

            lines = []
            for i, label in enumerate(IKE_KEY_LABELS):
                if i < len(arg_addrs) and arg_addrs[i] != 0:
                    key_hex = read_key_material(arg_addrs[i], label)
                    if key_hex:
                        line = f"IPSEC_{label.upper()} {key_hex}"
                        lines.append(line)

            if lines:
                with open(KEYLOG_FILE, "a") as f:
                    for line in lines:
                        f.write(line + "\n")
                print(f"[IPSec] Extracted {len(lines)} IKE SA keys")

        except Exception as e:
            print(f"[IPSec] Error in derive_ike_keys: {e}")

        return False


def main():
    print("=" * 60)
    print("friTap IPSec Key Extractor (GDB) -- strongSwan")
    print(f"Writing keys to: {KEYLOG_FILE}")
    print("=" * 60)

    try:
        _child_bp = DeriveChildSaKeysBreakpoint()
        _ike_bp = DeriveIkeKeysBreakpoint()
    except Exception as e:
        print(f"[IPSec] Failed to set breakpoints: {e}")
        print("[IPSec] Make sure the target is strongSwan charon with debug symbols.")
        return

    print("[IPSec] Breakpoints set. Continuing execution...")
    print("[IPSec] Press Ctrl+C to stop and collect results.")
    gdb.execute("continue")


if __name__ == "__main__":
    main()
else:
    main()
