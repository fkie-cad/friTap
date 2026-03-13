"""GDB adapter implementing the MemoryReader protocol."""

import struct

# gdb module is only available inside GDB
import gdb

from ..memory import ARCH_REGISTER_MAP


class GdbMemoryReader:
    """MemoryReader implementation for GDB."""

    def __init__(self):
        self._ptr_size = None
        self._arch = None
        self._inferior = None

    def _get_inferior(self):
        """Lazily cache the selected inferior."""
        if self._inferior is None:
            self._inferior = gdb.selected_inferior()
        return self._inferior

    def _detect_arch(self):
        if self._arch is not None:
            return
        try:
            arch_name = gdb.selected_frame().architecture().name()
            if "i386" in arch_name or ("arm" in arch_name and "aarch64" not in arch_name):
                self._ptr_size = 4
                self._arch = "i386"
            elif "aarch64" in arch_name:
                self._ptr_size = 8
                self._arch = "aarch64"
            else:
                self._ptr_size = 8
                self._arch = "x86_64"
        except Exception:
            self._ptr_size = 8
            self._arch = "x86_64"

    def get_pointer_size(self):
        self._detect_arch()
        return self._ptr_size

    def get_arch(self):
        self._detect_arch()
        return self._arch

    def read_pointer(self, addr):
        ptr_size = self.get_pointer_size()
        inferior = self._get_inferior()
        data = inferior.read_memory(addr, ptr_size).tobytes()
        fmt = "<Q" if ptr_size == 8 else "<I"
        return struct.unpack(fmt, data)[0]

    def read_uint32(self, addr):
        inferior = self._get_inferior()
        data = inferior.read_memory(addr, 4).tobytes()
        return struct.unpack("<I", data)[0]

    def read_bytes(self, addr, length):
        inferior = self._get_inferior()
        return inferior.read_memory(addr, length).tobytes()

    def read_string(self, addr, max_len=128):
        inferior = self._get_inferior()
        data = inferior.read_memory(addr, max_len).tobytes()
        null_idx = data.find(b'\x00')
        if null_idx >= 0:
            data = data[:null_idx]
        return data.decode('utf-8', errors='replace')

    def read_register(self, name):
        """Read a register by abstract name (arg0, arg1, ...) or raw name ($rdi, etc)."""
        self._detect_arch()
        # Resolve abstract names
        if name.startswith("arg"):
            reg_map = ARCH_REGISTER_MAP.get(self._arch, {})
            concrete = reg_map.get(name, name)
            if concrete.startswith("stack+"):
                # Read from stack for i386 cdecl
                offset = int(concrete.split("+")[1])
                sp = int(gdb.parse_and_eval("$esp"))
                return self.read_pointer(sp + offset + self._ptr_size)  # skip return addr
            return int(gdb.parse_and_eval(concrete))
        return int(gdb.parse_and_eval(name))

    def execute_finish(self):
        """Run until the current function returns."""
        gdb.execute("finish")
