"""Memory reading protocol and architecture register mappings."""

try:
    from typing import Protocol
except ImportError:
    Protocol = object  # type: ignore


class MemoryReader(Protocol):
    """Abstract interface for reading process memory.

    Debugger-specific adapters (GDB, LLDB) implement this protocol
    to provide uniform memory access across debugger backends.
    """

    def read_pointer(self, addr: int) -> int:
        """Read a pointer-sized value at the given address."""
        ...

    def read_uint32(self, addr: int) -> int:
        """Read an unsigned 32-bit integer at the given address."""
        ...

    def read_bytes(self, addr: int, length: int) -> bytes:
        """Read raw bytes from the given address."""
        ...

    def read_string(self, addr: int, max_len: int = 128) -> str:
        """Read a null-terminated string from the given address."""
        ...

    def get_pointer_size(self) -> int:
        """Return the pointer size in bytes (4 or 8)."""
        ...

    def read_register(self, name: str) -> int:
        """Read the value of a named register."""
        ...


# Maps abstract argument names to concrete register names per architecture.
# For stack-based calling conventions (i386/cdecl), "stack+N" indicates
# the argument is at [SP + N] after the return address.
ARCH_REGISTER_MAP = {
    "x86_64": {
        "arg0": "$rdi",
        "arg1": "$rsi",
        "arg2": "$rdx",
        "arg3": "$rcx",
        "arg4": "$r8",
        "arg5": "$r9",
    },
    "aarch64": {
        "arg0": "x0",
        "arg1": "x1",
        "arg2": "x2",
        "arg3": "x3",
        "arg4": "x4",
        "arg5": "x5",
        "arg6": "x6",
        "arg7": "x7",
    },
    "i386": {
        # cdecl: arguments passed on the stack
        "arg0": "stack+0",
        "arg1": "stack+4",
        "arg2": "stack+8",
        "arg3": "stack+12",
    },
}
