"""Core dataclasses for extraction definitions."""

import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import List, Optional, Dict, Union

# Regex ensuring each operator is a single +, -, *, or / between digits (no ** possible)
_SAFE_EXPR_RE = re.compile(r"^\d+(\s*[+\-*/]\s*\d+)*$")


@lru_cache(maxsize=128)
def resolve_offset(offset: Union[int, str], ptr_size: int) -> int:
    """Evaluate an offset that may contain pointer-size-dependent expressions.

    Args:
        offset: Either an integer offset or a string expression like "32+ptr_size".
        ptr_size: The pointer size in bytes (4 or 8).

    Returns:
        The resolved integer offset.

    Examples:
        >>> resolve_offset(16, 8)
        16
        >>> resolve_offset("32+ptr_size", 8)
        40
        >>> resolve_offset("ptr_size*2", 4)
        8
    """
    if isinstance(offset, int):
        return offset
    # Replace ptr_size token with the actual value and evaluate
    expr = offset.replace("ptr_size", str(ptr_size))
    # Validate expression is strictly digits separated by single arithmetic operators
    if not _SAFE_EXPR_RE.match(expr.strip()):
        raise ValueError(f"Unsafe offset expression: {offset!r}")
    return int(eval(expr))  # noqa: S307 — expression is validated by regex above


@dataclass(frozen=True)
class StructField:
    """A single field to extract from a struct in memory.

    Attributes:
        name: Identifier for this field (used in output labels and size references).
        offset: Byte offset from the struct base. Can be an int or a string
                expression like "32+ptr_size" for pointer-size-dependent layouts.
        read_type: How to interpret the memory at this offset.
            - "pointer": read a native-width pointer value
            - "uint32": read a 32-bit unsigned integer
            - "string": read a null-terminated C string directly at this offset
            - "bytes": read raw bytes at this offset (size from size_from_field)
            - "deref_string": read a pointer at this offset, then read a
              null-terminated string at the dereferenced address
            - "deref_bytes": read a pointer at this offset, then read N bytes
              from the dereferenced address (N from size_from_field). If
              ptr_field is set, use that field's value as the address instead.
        size_from_field: For "bytes" and "deref_bytes", the name of another
                         StructField whose extracted value gives the byte count.
        ptr_field: For "deref_bytes", optionally use a previously extracted
                   field's value as the pointer address instead of reading a new
                   pointer at this field's offset.
    """
    name: str
    offset: Union[int, str]
    read_type: str
    size_from_field: Optional[str] = None

    ptr_field: Optional[str] = None

    def __post_init__(self) -> None:
        valid_types = (
            "pointer", "uint32", "string", "bytes",
            "deref_string", "deref_bytes",
        )
        if self.read_type not in valid_types:
            raise ValueError(
                f"read_type must be one of {valid_types}, got {self.read_type!r}"
            )
        if self.read_type == "bytes" and self.size_from_field is None:
            raise ValueError(
                "size_from_field is required when read_type is 'bytes'"
            )
        if self.read_type == "deref_bytes" and self.size_from_field is None:
            raise ValueError(
                "size_from_field is required when read_type is 'deref_bytes'"
            )


@dataclass(frozen=True)
class StructExtraction:
    """Describes how to navigate to a struct and which fields to extract.

    Attributes:
        base_arg: Abstract argument name, e.g. "arg0", "arg1".
        dereference_chain: List of offsets to follow pointers through nested
                           structs before reaching the target struct.
        fields: Fields to extract from the target struct.
        iterate: If present, the extraction is repeated for each label in the
                 list (e.g. ["client", "server"]), with the label available
                 as {direction} in output format strings. Each iteration
                 advances the base pointer by ptr_size.
        label: Static label for this extraction (used as {label} in output
               format strings). Useful when multiple independent extractions
               each produce a differently-named key.
    """
    base_arg: str
    dereference_chain: List[Union[int, str]] = field(default_factory=list)
    fields: List[StructField] = field(default_factory=list)
    iterate: Optional[List[str]] = None
    label: Optional[str] = None


@dataclass(frozen=True)
class BreakpointSpec:
    """Specifies where to break and what to extract.

    Attributes:
        function_name: Symbol name to set the breakpoint on.
        timing: When to extract data — "on_return" or "on_entry".
        struct_extractions: List of struct extractions to perform when the
                            breakpoint is hit.
        output_labels: Maps field names to output format strings,
                       e.g. {"key": "SSH_ENC_KEY_{direction} {hex}"}.
                       Supports {direction} (from iterate), {label} (from
                       StructExtraction.label), and {hex} placeholders.
        capture_args_on_entry: If True, argument register values are captured
                               when the breakpoint is first hit (on entry),
                               then struct extractions run after the function
                               returns. This is needed when output parameters
                               are passed via registers that get clobbered
                               during execution (e.g. IPSec key derivation).
    """
    function_name: str
    timing: str
    struct_extractions: List[StructExtraction] = field(default_factory=list)
    output_labels: Dict[str, str] = field(default_factory=dict)
    capture_args_on_entry: bool = False

    def __post_init__(self) -> None:
        valid_timings = ("on_return", "on_entry")
        if self.timing not in valid_timings:
            raise ValueError(
                f"timing must be one of {valid_timings}, got {self.timing!r}"
            )


@dataclass(frozen=True)
class ExtractionDefinition:
    """Complete definition for a protocol/library extraction.

    Attributes:
        protocol: Protocol name, e.g. "tls", "ssh", "ipsec".
        library: Library name, e.g. "openssl", "libssh".
        breakpoints: List of breakpoint specifications.
        keylog_env_var: Environment variable for the keylog file path.
        default_keylog_file: Default file path if the env var is not set.
    """
    protocol: str
    library: str
    breakpoints: List[BreakpointSpec] = field(default_factory=list)
    keylog_env_var: str = ""
    default_keylog_file: str = ""
