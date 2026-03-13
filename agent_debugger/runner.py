"""Generic extraction engine for debugger-based key extraction.

Consumes an ExtractionDefinition + MemoryReader to extract cryptographic
keys from a running process.  Supports two patterns:

Pattern 1 (SSH): Single base arg -> dereference chain -> iterate over
    ["client", "server"] -> read struct fields -> format output.
Pattern 2 (IPSec): Multiple struct_extractions, each with its own
    base_arg and label -> read key_material_t fields -> format output.
"""

from typing import Any, Dict, List, Optional

from .definitions.base import (
    BreakpointSpec,
    ExtractionDefinition,
    StructField,
    resolve_offset,
)
from .output import KeylogWriter


class ExtractionRunner:
    """Executes struct extractions using a MemoryReader and writes output."""

    def __init__(self, definition, writer):
        # type: (ExtractionDefinition, KeylogWriter) -> None
        self.definition = definition
        self.writer = writer
        self._proto = definition.protocol.upper()

    def read_field(self, reader, base_addr, field, extracted, ptr_size):
        # type: (Any, int, StructField, Dict[str, Any], int) -> Any
        """Read a single StructField from memory.

        Args:
            reader: MemoryReader implementation.
            base_addr: Base address of the struct.
            field: StructField to read.
            extracted: Dict of already-extracted field values
                       (for size_from_field / ptr_field references).
            ptr_size: Pointer size in bytes (4 or 8).

        Returns:
            The extracted value (int, str, or bytes depending on read_type).
        """
        offset = resolve_offset(field.offset, ptr_size)
        addr = base_addr + offset

        if field.read_type == "pointer":
            return reader.read_pointer(addr)

        if field.read_type == "uint32":
            return reader.read_uint32(addr)

        if field.read_type == "string":
            return reader.read_string(addr)

        if field.read_type == "deref_string":
            ptr = reader.read_pointer(addr)
            if ptr == 0:
                return ""
            return reader.read_string(ptr, 64)

        if field.read_type == "bytes":
            size = extracted[field.size_from_field]
            if size <= 0 or size >= 4096:
                return b""
            return reader.read_bytes(addr, size)

        if field.read_type == "deref_bytes":
            size = extracted[field.size_from_field]
            if size <= 0 or size >= 4096:
                return b""
            if field.ptr_field:
                ptr = extracted[field.ptr_field]
            else:
                ptr = reader.read_pointer(addr)
            if ptr == 0:
                return b""
            return reader.read_bytes(ptr, size)

        raise ValueError("Unknown read_type: {!r}".format(field.read_type))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_fields(self, reader, struct_addr, fields, ptr_size):
        # type: (Any, int, List[StructField], int) -> Dict[str, Any]
        """Extract all fields from a struct, skipping individual failures."""
        extracted = {}  # type: Dict[str, Any]
        for field in fields:
            try:
                value = self.read_field(reader, struct_addr, field, extracted, ptr_size)
                extracted[field.name] = value
            except Exception:
                continue
        return extracted

    def _format_lines(self, extracted, output_labels, direction=None, label=None):
        # type: (Dict[str, Any], Dict[str, str], Optional[str], Optional[str]) -> List[str]
        """Format extracted fields into output lines using template strings."""
        lines = []  # type: List[str]
        for field_name, template in output_labels.items():
            if field_name not in extracted:
                continue
            value = extracted[field_name]
            if isinstance(value, bytes):
                if len(value) == 0:
                    continue
                hex_str = value.hex()
            elif isinstance(value, int):
                hex_str = format(value, "x")
            elif isinstance(value, str):
                hex_str = value
            else:
                continue
            line = template.replace("{hex}", hex_str)
            if direction is not None:
                line = line.replace("{direction}", direction.upper())
            if label is not None:
                line = line.replace("{label}", label.upper())
            lines.append(line)
        return lines

    # ------------------------------------------------------------------
    # Main extraction entry point
    # ------------------------------------------------------------------

    def run_extraction(self, reader, bp_spec, captured_args=None):
        # type: (Any, BreakpointSpec, Optional[Dict[str, int]]) -> List[str]
        """Execute all struct extractions for a breakpoint.

        Args:
            reader: MemoryReader implementation.
            bp_spec: BreakpointSpec defining what to extract.
            captured_args: Dict of {arg_name: value} captured on entry
                           (used when capture_args_on_entry is True).

        Returns:
            List of formatted output lines.
        """
        lines = []  # type: List[str]
        ptr_size = reader.get_pointer_size()

        for extraction in bp_spec.struct_extractions:
            try:
                # Resolve the base address from captured args or registers
                if captured_args and extraction.base_arg in captured_args:
                    base_addr = captured_args[extraction.base_arg]
                else:
                    base_addr = reader.read_register(extraction.base_arg)

                if base_addr == 0:
                    continue

                # Walk the dereference chain to reach the target struct
                addr = base_addr
                for deref_offset in extraction.dereference_chain:
                    resolved = resolve_offset(deref_offset, ptr_size)
                    addr = reader.read_pointer(addr + resolved)
                    if addr == 0:
                        break

                if addr == 0:
                    continue

                if extraction.iterate:
                    # Pattern 1: iterate for each label, advancing by ptr_size
                    for i, direction in enumerate(extraction.iterate):
                        try:
                            iter_addr = reader.read_pointer(
                                addr + i * ptr_size
                            )
                            if iter_addr == 0:
                                continue
                            extracted = self._extract_fields(
                                reader, iter_addr, extraction.fields, ptr_size
                            )
                            lines.extend(
                                self._format_lines(
                                    extracted,
                                    bp_spec.output_labels,
                                    direction=direction,
                                )
                            )
                        except Exception as exc:
                            print(
                                "[{}] Error in iteration {}: {}".format(
                                    self._proto,
                                    direction,
                                    exc,
                                )
                            )
                else:
                    # Pattern 2: single extraction (e.g. IPSec)
                    extracted = self._extract_fields(
                        reader, addr, extraction.fields, ptr_size
                    )
                    lines.extend(
                        self._format_lines(
                            extracted,
                            bp_spec.output_labels,
                            label=extraction.label or "",
                        )
                    )

            except Exception as exc:
                print(
                    "[{}] Extraction error: {}".format(
                        self._proto, exc
                    )
                )

        return lines

    def write_results(self, lines):
        # type: (List[str]) -> None
        """Write extracted key lines to the keylog file."""
        self.writer.write_lines(lines)
        if lines:
            print(
                "[{}] Extracted {} keys".format(
                    self._proto, len(lines)
                )
            )


# ======================================================================
# Factory: GDB
# ======================================================================

def create_gdb_runner(definition):
    # type: (ExtractionDefinition) -> List[Any]
    """Create GDB breakpoint objects for an extraction definition.

    Each BreakpointSpec in the definition becomes a
    ``_DefinitionBreakpoint`` (a ``gdb.Breakpoint`` subclass) that
    handles all three cases:

    * No ``struct_extractions`` -- just log that the function was hit.
    * ``capture_args_on_entry`` -- capture register values on entry,
      ``finish``, then extract.
    * Otherwise -- optionally ``finish`` (for ``on_return``), then
      extract.

    The class-variable closure pattern (``_spec``, ``_runner``, etc.)
    is intentional: Python closures over loop variables would bind to
    the *last* value.  Class attributes are evaluated at class-creation
    time and therefore capture the correct per-iteration value.

    Returns:
        A list of live ``gdb.Breakpoint`` instances.
    """
    import gdb  # noqa: F811 — only available inside GDB
    from .adapters.gdb_adapter import GdbMemoryReader

    writer = KeylogWriter(definition.keylog_env_var, definition.default_keylog_file)
    reader = GdbMemoryReader()
    runner = ExtractionRunner(definition, writer)

    breakpoints = []  # type: List[Any]
    proto = definition.protocol.upper()

    for bp_spec in definition.breakpoints:
        # Precompute the set of arg names to capture (empty if not needed)
        capture_args = frozenset(
            ext.base_arg for ext in bp_spec.struct_extractions
        ) if bp_spec.capture_args_on_entry else frozenset()

        class _DefinitionBreakpoint(gdb.Breakpoint):
            _spec = bp_spec
            _runner = runner
            _reader = reader
            _proto = proto
            _capture_args = capture_args

            def __init__(self):
                super(_DefinitionBreakpoint, self).__init__(
                    self._spec.function_name, gdb.BP_BREAKPOINT
                )
                print(
                    "[{}] Breakpoint set on {}".format(
                        self._proto, self._spec.function_name
                    )
                )

            def stop(self):
                try:
                    print(
                        "[{}] {} hit".format(
                            self._proto, self._spec.function_name
                        )
                    )

                    if not self._spec.struct_extractions:
                        # Logging-only breakpoint
                        return False

                    if self._capture_args:
                        # Capture registers on entry, then finish
                        captured = {}  # type: Dict[str, int]
                        for arg_name in self._capture_args:
                            try:
                                captured[arg_name] = self._reader.read_register(
                                    arg_name
                                )
                            except Exception:
                                captured[arg_name] = 0
                        gdb.execute("finish")
                        lines = self._runner.run_extraction(
                            self._reader, self._spec, captured
                        )
                    else:
                        if self._spec.timing == "on_return":
                            gdb.execute("finish")
                        lines = self._runner.run_extraction(
                            self._reader, self._spec
                        )

                    self._runner.write_results(lines)
                except Exception as exc:
                    print("[{}] Error: {}".format(self._proto, exc))
                return False

        breakpoints.append(_DefinitionBreakpoint())

    return breakpoints


# ======================================================================
# Factory: LLDB
# ======================================================================

def create_lldb_runner(definition, debugger):
    # type: (ExtractionDefinition, Any) -> None
    """Create LLDB breakpoints for an extraction definition.

    Sets breakpoints by symbol name on the selected target.  LLDB
    breakpoint callback registration is left to the caller because
    the callback mechanism differs between scripted and interactive
    LLDB sessions.

    Args:
        definition: The extraction definition describing which functions
                    to break on.
        debugger: The ``lldb.SBDebugger`` instance (passed by LLDB when
                  loading a script).
    """
    import lldb  # noqa: F811 — only available inside LLDB
    from .adapters.lldb_adapter import LldbMemoryReader

    writer = KeylogWriter(definition.keylog_env_var, definition.default_keylog_file)
    proto = definition.protocol.upper()
    target = debugger.GetSelectedTarget()

    if not target.IsValid():
        print(
            "[{}] No valid target.".format(proto)
        )
        return

    process = target.GetProcess()
    reader = LldbMemoryReader(process)
    runner = ExtractionRunner(definition, writer)

    for bp_spec in definition.breakpoints:
        bp = target.BreakpointCreateByName(bp_spec.function_name)
        if bp.IsValid():
            print(
                "[{}] Breakpoint set on {}".format(
                    proto, bp_spec.function_name
                )
            )
        else:
            print(
                "[{}] {} not found".format(proto, bp_spec.function_name)
            )


# ======================================================================
# Entry-point helpers
# ======================================================================

def run_gdb_main(definition):
    # type: (ExtractionDefinition) -> None
    """Top-level GDB entry point: print banner, create breakpoints, continue.

    Intended to be the single call in a GDB entry-point shim after
    setting up ``sys.path`` and importing the definition.
    """
    import gdb  # noqa: F811

    proto = definition.protocol.upper()
    print("[{}] {} key extraction loaded".format(proto, definition.library))

    try:
        create_gdb_runner(definition)
    except Exception as exc:
        print("[{}] Failed to create breakpoints: {}".format(proto, exc))
        return

    gdb.execute("continue")


def run_lldb_main(definition, debugger):
    # type: (ExtractionDefinition, Any) -> None
    """Top-level LLDB entry point: print banner, create breakpoints, continue.

    Intended to be the single call in an LLDB entry-point shim after
    setting up ``sys.path`` and importing the definition.
    """
    import lldb  # noqa: F811

    proto = definition.protocol.upper()
    print("[{}] {} key extraction loaded".format(proto, definition.library))

    try:
        create_lldb_runner(definition, debugger)
    except Exception as exc:
        print("[{}] Failed to create breakpoints: {}".format(proto, exc))
        return

    target = debugger.GetSelectedTarget()
    if target.IsValid():
        process = target.GetProcess()
        if process.IsValid():
            process.Continue()
