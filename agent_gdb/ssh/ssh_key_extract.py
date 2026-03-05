#!/usr/bin/env python3
"""
Standalone GDB script for SSH key extraction from OpenSSH.

Usage:
    gdb -x ssh_key_extract.py -p <sshd_pid>
    gdb -batch -x ssh_key_extract.py -p <sshd_pid>

Sets breakpoints on kex_derive_keys() and ssh_set_newkeys(),
then reads the sshenc struct to extract cipher keys and IVs.

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
    print("Usage: gdb -x ssh_key_extract.py -p <sshd_pid>")
    sys.exit(1)

# Output file for extracted keys
KEYLOG_FILE = os.environ.get("SSH_KEYLOG_FILE", "ssh_keys.log")

# sshenc struct offsets (OpenSSH 9.x / 10.x)
SSHENC_CIPHER_NAME_OFFSET = 0
SSHENC_KEY_LEN_OFFSET = 20
SSHENC_IV_LEN_OFFSET = 24
SSHENC_KEY_PTR_OFFSET = 32


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


def read_uint32(addr):
    """Read a 32-bit unsigned int."""
    inferior = gdb.selected_inferior()
    data = inferior.read_memory(addr, 4).tobytes()
    return struct.unpack("<I", data)[0]


def read_string(addr, max_len=128):
    """Read a null-terminated C string."""
    inferior = gdb.selected_inferior()
    data = inferior.read_memory(addr, max_len).tobytes()
    null_idx = data.find(b'\x00')
    if null_idx >= 0:
        data = data[:null_idx]
    return data.decode('utf-8', errors='replace')


def read_bytes(addr, length):
    """Read raw bytes from inferior memory."""
    inferior = gdb.selected_inferior()
    return inferior.read_memory(addr, length).tobytes()


def extract_sshenc_keys(sshenc_addr, direction):
    """Read cipher name, key, and IV from an sshenc struct."""
    results = []
    try:
        cipher_name_ptr = read_pointer(sshenc_addr + SSHENC_CIPHER_NAME_OFFSET)
        cipher_name = read_string(cipher_name_ptr, 64)
        key_len = read_uint32(sshenc_addr + SSHENC_KEY_LEN_OFFSET)
        iv_len = read_uint32(sshenc_addr + SSHENC_IV_LEN_OFFSET)
        ptr_size = get_pointer_size()
        key_ptr = read_pointer(sshenc_addr + SSHENC_KEY_PTR_OFFSET)
        iv_ptr = read_pointer(sshenc_addr + SSHENC_KEY_PTR_OFFSET + ptr_size)

        if key_len > 0 and key_len < 256 and key_ptr != 0:
            key_data = read_bytes(key_ptr, key_len)
            key_hex = key_data.hex()
            line = f"SSH_ENC_KEY_{direction.upper()} {key_hex}"
            results.append(line)
            print(f"[SSH] {direction} key: cipher={cipher_name}, len={key_len}")

        if iv_len > 0 and iv_len < 256 and iv_ptr != 0:
            iv_data = read_bytes(iv_ptr, iv_len)
            iv_hex = iv_data.hex()
            line = f"SSH_IV_{direction.upper()} {iv_hex}"
            results.append(line)
            print(f"[SSH] {direction} IV: cipher={cipher_name}, len={iv_len}")

    except Exception as e:
        print(f"[SSH] Error reading sshenc at 0x{sshenc_addr:x}: {e}")

    return results


class KexDeriveKeysBreakpoint(gdb.Breakpoint):
    """Breakpoint on kex_derive_keys() to capture SSH keys."""

    def __init__(self):
        super().__init__("kex_derive_keys", gdb.BP_BREAKPOINT)
        self._keylog_lines = []
        print("[SSH] Breakpoint set on kex_derive_keys")

    def stop(self):
        """Called when breakpoint is hit."""
        try:
            frame = gdb.selected_frame()
            # arg0 = struct ssh *
            ssh_ptr = int(frame.read_var("ssh")) if frame.function() else 0
            if ssh_ptr == 0:
                # Try reading from register (first argument)
                ssh_ptr = int(gdb.parse_and_eval("$rdi"))

            print(f"[SSH] kex_derive_keys hit, ssh=0x{ssh_ptr:x}")

            # Set a temporary breakpoint on return to read the keys
            gdb.execute("finish")

            # After finish, read keys from the struct
            if ssh_ptr != 0:
                state_ptr = read_pointer(ssh_ptr)
                if state_ptr != 0:
                    ptr_size = get_pointer_size()
                    for mode in range(2):
                        direction = "client" if mode == 0 else "server"
                        try:
                            newkeys_ptr = read_pointer(state_ptr + mode * ptr_size)
                            if newkeys_ptr != 0:
                                lines = extract_sshenc_keys(newkeys_ptr, direction)
                                self._keylog_lines.extend(lines)
                                # Write to keylog file
                                with open(KEYLOG_FILE, "a") as f:
                                    for line in lines:
                                        f.write(line + "\n")
                        except Exception as e:
                            print(f"[SSH] Error reading newkeys[{mode}]: {e}")

        except Exception as e:
            print(f"[SSH] Error in kex_derive_keys breakpoint: {e}")

        return False  # Don't stop, continue execution


class SshSetNewkeysBreakpoint(gdb.Breakpoint):
    """Breakpoint on ssh_set_newkeys() for key activation tracking."""

    def __init__(self):
        super().__init__("ssh_set_newkeys", gdb.BP_BREAKPOINT)
        print("[SSH] Breakpoint set on ssh_set_newkeys")

    def stop(self):
        try:
            _frame = gdb.selected_frame()
            try:
                mode = int(gdb.parse_and_eval("$rsi"))
            except Exception:
                mode = -1
            direction = "client" if mode == 0 else "server" if mode == 1 else f"mode={mode}"
            print(f"[SSH] New keys activated: {direction}")
        except Exception as e:
            print(f"[SSH] Error in ssh_set_newkeys breakpoint: {e}")
        return False


def main():
    print("=" * 60)
    print("friTap SSH Key Extractor (GDB)")
    print(f"Writing keys to: {KEYLOG_FILE}")
    print("=" * 60)

    # Set breakpoints
    try:
        _kex_bp = KexDeriveKeysBreakpoint()
        _newkeys_bp = SshSetNewkeysBreakpoint()
    except Exception as e:
        print(f"[SSH] Failed to set breakpoints: {e}")
        print("[SSH] Make sure the target has debug symbols or is OpenSSH.")
        return

    # Continue execution
    print("[SSH] Breakpoints set. Continuing execution...")
    print("[SSH] Press Ctrl+C to stop and collect results.")
    gdb.execute("continue")


if __name__ == "__main__":
    main()
else:
    # Auto-run when sourced via gdb -x
    main()
