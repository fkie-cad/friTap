"""LLDB adapter implementing the MemoryReader protocol."""

import struct

import lldb

from ..memory import ARCH_REGISTER_MAP


class LldbMemoryReader:
    """MemoryReader implementation for LLDB."""

    def __init__(self, process, frame=None):
        self._process = process
        self._frame = frame
        self._arch = None
        self._error = lldb.SBError()
        self._ptr_size = process.GetAddressByteSize()

    def _detect_arch(self):
        if self._arch is not None:
            return
        target = self._process.GetTarget()
        triple = target.GetTriple()
        if "x86_64" in triple or "amd64" in triple:
            self._arch = "x86_64"
        elif "aarch64" in triple or "arm64" in triple:
            self._arch = "aarch64"
        elif "i386" in triple or "i686" in triple:
            self._arch = "i386"
        else:
            self._arch = "x86_64"

    def get_pointer_size(self):
        return self._ptr_size

    def get_arch(self):
        self._detect_arch()
        return self._arch

    def read_pointer(self, addr):
        ptr_size = self.get_pointer_size()
        error = self._error
        data = self._process.ReadMemory(addr, ptr_size, error)
        if error.Fail():
            raise RuntimeError("Pointer read at 0x{:x}: {}".format(addr, error.GetCString()))
        fmt = "<Q" if ptr_size == 8 else "<I"
        return struct.unpack(fmt, data)[0]

    def read_uint32(self, addr):
        error = self._error
        data = self._process.ReadMemory(addr, 4, error)
        if error.Fail():
            raise RuntimeError("uint32 read at 0x{:x}: {}".format(addr, error.GetCString()))
        return struct.unpack("<I", data)[0]

    def read_bytes(self, addr, length):
        error = self._error
        data = self._process.ReadMemory(addr, length, error)
        if error.Fail():
            raise RuntimeError("Read at 0x{:x}: {}".format(addr, error.GetCString()))
        return data

    def read_string(self, addr, max_len=128):
        error = self._error
        data = self._process.ReadMemory(addr, max_len, error)
        if error.Fail():
            raise RuntimeError("String read at 0x{:x}: {}".format(addr, error.GetCString()))
        null_idx = data.find(b'\x00')
        if null_idx >= 0:
            data = data[:null_idx]
        return data.decode('utf-8', errors='replace')

    def read_register(self, name):
        """Read a register by abstract name or LLDB register name."""
        self._detect_arch()
        if name.startswith("arg"):
            reg_map = ARCH_REGISTER_MAP.get(self._arch, {})
            concrete = reg_map.get(name, name)
            if concrete.startswith("stack+"):
                offset = int(concrete.split("+")[1])
                sp_val = self._frame.FindRegister("sp")
                sp = sp_val.GetValueAsUnsigned()
                ptr_size = self.get_pointer_size()
                return self.read_pointer(sp + offset + ptr_size)
            if self._frame:
                reg_val = self._frame.FindRegister(concrete)
                if reg_val.IsValid():
                    return reg_val.GetValueAsUnsigned()
            raise RuntimeError("Cannot read register {}".format(concrete))
        if self._frame:
            reg_val = self._frame.FindRegister(name)
            if reg_val.IsValid():
                return reg_val.GetValueAsUnsigned()
        raise RuntimeError("Register {} not found".format(name))
