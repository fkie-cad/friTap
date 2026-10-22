"""Optional schema-based protobuf decoding.

Requires the ``google-protobuf`` package (``pip install protobuf``).
An :class:`ImportError` is raised at construction time if the package
is not installed, so callers can gracefully fall back to schema-less
decoding.

Usage::

    from friTap.parsers.protobuf.schema import SchemaDecoder

    decoder = SchemaDecoder()  # raises ImportError if protobuf missing
    decoder.load_descriptor("api_descriptor.desc", "mypackage.MyMessage")
    result = decoder.decode(raw_bytes)

    # .proto sources are compiled with ``protoc`` (must be on PATH):
    decoder.load_schema("api.proto", "mypackage.MyMessage")
    print(decoder.decode_text(raw_bytes))
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
from collections import OrderedDict, namedtuple
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Optional, Sequence

from .wire import decode_varint

_log = logging.getLogger(__name__)

_PROTO_SUFFIX = ".proto"


class SchemaError(Exception):
    """A schema could not be compiled or loaded; ``stderr`` holds protoc output."""

    def __init__(self, message: str, stderr: str = "") -> None:
        super().__init__(message)
        self.stderr = stderr


def compile_proto(
    path: str | Path,
    include_paths: Sequence[str | Path] = (),
    timeout: float = 5.0,
) -> bytes:
    """Compile a ``.proto`` file into serialized ``FileDescriptorSet`` bytes.

    Runs ``protoc --include_imports`` (so imported files are part of the
    set), with the file's own directory plus *include_paths* as proto paths.
    Results are cached per (real path, include paths) and stay valid only
    while every input file is unchanged: the schema itself and each file it
    imports (by mtime and size), so editing an imported ``.proto`` recompiles
    too. A protoc failure is cached the same way and re-raised as an equal
    :class:`SchemaError` until one of the files involved changes, so a broken
    schema is not recompiled on every preview.

    Raises:
        SchemaError: protoc is missing, fails, or times out (``stderr`` set).
        FileNotFoundError: *path* does not exist.
    """
    real = os.path.realpath(path)
    os.stat(real)  # FileNotFoundError for a missing schema, before protoc runs
    includes = tuple(os.path.realpath(p) for p in include_paths)
    return _compile_proto_cached(real, includes, timeout)


#: ``(path, (mtime_ns, size) or None when the file is absent)``.
_FileStat = tuple[str, Optional[tuple[int, int]]]

CompileCacheInfo = namedtuple("CompileCacheInfo", "hits misses maxsize currsize")

# A protoc diagnostic names files as ``path:line:col:`` / ``path: File not
# found.`` at a line start, or quotes them (``Import "x.proto" was not found``).
_STDERR_PROTO_NAME = re.compile(r'"([^"\n]+\.proto)"|^([^:\n]+\.proto):', re.MULTILINE)

# ``import "x.proto";`` / ``import public "x.proto";`` / ``import weak ...``.
_IMPORT_STATEMENT = re.compile(
    r'^\s*import\s+(?:public\s+|weak\s+)?"([^"\n]+)"\s*;', re.MULTILINE)

# Upper bound on files read while following imports of a failed compile.
_MAX_IMPORT_SCAN = 256


def _file_stat(path: str) -> Optional[tuple[int, int]]:
    """``(mtime_ns, size)`` of *path*, or ``None`` when it cannot be stat'ed."""
    try:
        stat = os.stat(path)
    except OSError:
        return None
    return stat.st_mtime_ns, stat.st_size


@dataclass(frozen=True)
class _CompileOutcome:
    """One protoc run: the descriptor set or the failure, plus its inputs."""

    input_stats: tuple[_FileStat, ...]
    descriptor: bytes = b""
    error: Optional[SchemaError] = None

    def is_current(self) -> bool:
        """True while no recorded input file was edited, created or removed."""
        return all(_file_stat(path) == stat for path, stat in self.input_stats)

    def result(self) -> bytes:
        """The descriptor bytes, or a fresh copy of the cached failure raised."""
        if self.error is not None:
            raise SchemaError(str(self.error), stderr=self.error.stderr)
        return self.descriptor


class _ProtoCompileCache:
    """LRU cache of protoc outcomes, validated against input-file stats.

    ``functools.lru_cache`` cannot express this: imported files are only
    known after compiling, so their stats cannot be part of the key. Keeps
    the ``cache_clear()`` / ``cache_info()`` interface of an ``lru_cache``.
    """

    def __init__(self, maxsize: int) -> None:
        self._maxsize = maxsize
        self._entries: OrderedDict[tuple, _CompileOutcome] = OrderedDict()
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0

    def __call__(
        self, real_path: str, include_paths: tuple[str, ...], timeout: float,
    ) -> bytes:
        key = (real_path, include_paths, timeout)
        outcome = self._lookup(key)
        if outcome is None:
            outcome = _compile_outcome(real_path, include_paths, timeout)
            self._store(key, outcome)
        return outcome.result()

    def _lookup(self, key: tuple) -> Optional[_CompileOutcome]:
        with self._lock:
            outcome = self._entries.get(key)
            if outcome is not None and outcome.is_current():
                self._entries.move_to_end(key)
                self._hits += 1
                return outcome
            self._misses += 1
            return None

    def _store(self, key: tuple, outcome: _CompileOutcome) -> None:
        with self._lock:
            self._entries[key] = outcome
            self._entries.move_to_end(key)
            while len(self._entries) > self._maxsize:
                self._entries.popitem(last=False)

    def cache_clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._hits = self._misses = 0

    def cache_info(self) -> CompileCacheInfo:
        with self._lock:
            return CompileCacheInfo(self._hits, self._misses, self._maxsize,
                                    len(self._entries))


_compile_proto_cached = _ProtoCompileCache(maxsize=32)


def _compile_outcome(
    real_path: str, include_paths: tuple[str, ...], timeout: float,
) -> _CompileOutcome:
    """Run protoc once and record which files the result depends on.

    A missing protoc or a timeout raises directly (not cached: both can go
    away without any ``.proto`` changing); a protoc error is returned as a
    cacheable outcome.
    """
    protoc = shutil.which("protoc")
    if protoc is None:
        raise SchemaError("protoc not found on PATH (needed to compile .proto schemas)")
    proto_paths = (os.path.dirname(real_path), *include_paths)
    top_stat = _file_stat(real_path)  # before protoc reads it: an edit mid-run invalidates
    try:
        descriptor = _protoc_descriptor_set(protoc, proto_paths, real_path, timeout)
    except SchemaError as exc:
        if isinstance(exc.__cause__, subprocess.TimeoutExpired):
            raise
        # A diagnostic need not name the file to fix (``"a.B" is not
        # defined`` blames the importer), so also track every import.
        names = [*_proto_names_in_stderr(exc.stderr),
                 *_imported_names(real_path, proto_paths)]
        return _CompileOutcome(_input_stats(real_path, top_stat, names, proto_paths),
                               error=exc)
    names = _proto_names_in_descriptor_set(descriptor)
    return _CompileOutcome(_input_stats(real_path, top_stat, names, proto_paths),
                           descriptor=descriptor)


def _protoc_descriptor_set(
    protoc: str, proto_paths: Sequence[str], real_path: str, timeout: float,
) -> bytes:
    """Compile *real_path* with its imports into ``FileDescriptorSet`` bytes."""
    with tempfile.TemporaryDirectory(prefix="fritap-proto-") as tmp:
        out = os.path.join(tmp, "schema.desc")
        argv = [protoc, *(f"--proto_path={p}" for p in proto_paths),
                "--include_imports", f"--descriptor_set_out={out}", real_path]
        _run_protoc(argv, timeout)
        return Path(out).read_bytes()


def _input_stats(
    real_path: str, top_stat: Optional[tuple[int, int]],
    names: Sequence[str], proto_paths: Sequence[str],
) -> tuple[_FileStat, ...]:
    """Stats of the schema plus every file protoc could have read for *names*.

    A relative name is looked up along *proto_paths* like protoc does; every
    candidate up to the first existing one is recorded (absent ones as
    ``None``), so a file appearing earlier on the path, i.e. shadowing the
    one used, also invalidates. Names never on disk (protoc's built-in
    well-known types) stay ``None`` and so never invalidate.
    """
    stats: dict[str, Optional[tuple[int, int]]] = {real_path: top_stat}
    for name in names:
        for candidate in _resolution_candidates(name, proto_paths):
            stat = stats.setdefault(candidate, _file_stat(candidate))
            if stat is not None:
                break
    return tuple(sorted(stats.items()))


def _resolution_candidates(name: str, proto_paths: Sequence[str]) -> list[str]:
    """Disk paths protoc tries, in order, for the proto file *name*."""
    if os.path.isabs(name):
        return [name]
    return [os.path.normpath(os.path.join(path, name)) for path in proto_paths]


def _proto_names_in_stderr(stderr: str) -> list[str]:
    """``.proto`` names a protoc diagnostic mentions (errors and missing imports)."""
    return [quoted or leading
            for quoted, leading in _STDERR_PROTO_NAME.findall(stderr or "")]


def _imported_names(real_path: str, proto_paths: Sequence[str]) -> list[str]:
    """Transitive ``import`` names of *real_path*, read from the sources.

    Used when protoc failed and left no descriptor set. Best effort: an
    unreadable file contributes nothing; at most :data:`_MAX_IMPORT_SCAN`
    files are read.
    """
    names: list[str] = []
    pending = [real_path]
    seen = {real_path}
    while pending and len(seen) <= _MAX_IMPORT_SCAN:
        try:
            source = Path(pending.pop()).read_text(errors="replace")
        except OSError:
            continue
        for name in _IMPORT_STATEMENT.findall(source):
            names.append(name)
            found = next((c for c in _resolution_candidates(name, proto_paths)
                          if os.path.isfile(c)), None)
            if found is not None and found not in seen:
                seen.add(found)
                pending.append(found)
    return names


def _proto_names_in_descriptor_set(descriptor: bytes) -> list[str]:
    """``FileDescriptorProto.name`` of every file in a ``FileDescriptorSet``.

    Walks the wire format directly (``FileDescriptorSet.file`` = 1,
    ``FileDescriptorProto.name`` = 1) so no ``google.protobuf`` is needed.
    Malformed input yields the names read so far.
    """
    names: list[str] = []
    try:
        for file_proto in _length_delimited_fields(descriptor, 1):
            name = next(_length_delimited_fields(file_proto, 1), None)
            if name:
                names.append(name.decode("utf-8", "replace"))
    except (ValueError, IndexError):
        pass
    return names


def _length_delimited_fields(data: bytes, field_number: int) -> Iterator[bytes]:
    """Yield the top-level length-delimited fields numbered *field_number*.

    Stops at a group (descriptors never use them); raises ``ValueError`` on a
    malformed varint.
    """
    offset = 0
    while offset < len(data):
        tag, offset = decode_varint(data, offset)
        wire_type = tag & 0x07
        if wire_type == 0:
            _, offset = decode_varint(data, offset)
        elif wire_type == 1:
            offset += 8
        elif wire_type == 5:
            offset += 4
        elif wire_type == 2:
            length, offset = decode_varint(data, offset)
            if tag >> 3 == field_number:
                yield data[offset:offset + length]
            offset += length
        else:
            return


def _run_protoc(argv: list[str], timeout: float) -> None:
    """Run protoc; raise :class:`SchemaError` carrying stderr on failure."""
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise SchemaError(f"protoc timed out after {timeout:g}s") from exc
    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise SchemaError(f"protoc failed: {stderr}", stderr=stderr)


def _check_protobuf_available() -> None:
    """Raise ImportError with a helpful message if google.protobuf is missing."""
    try:
        import google.protobuf  # noqa: F401
    except ImportError:
        raise ImportError(
            "Schema-based protobuf decoding requires the 'protobuf' package. "
            "Install it with: pip install fritap[proto]"
        )


class SchemaDecoder:
    """Decode protobuf messages using compiled descriptor sets.

    Parameters
    ----------
    None

    Raises
    ------
    ImportError
        If ``google-protobuf`` is not installed.
    """

    def __init__(self) -> None:
        _check_protobuf_available()
        from google.protobuf import descriptor_pool
        self._pool = descriptor_pool.DescriptorPool()
        self._message_class: Any = None
        self._message_type_name: str = ""
        self._loaded_types: list[str] = []

    def load_descriptor(self, path: str | Path, message_type: str) -> None:
        """Load a compiled descriptor set (.desc) file and select a message type.

        Generate a descriptor set with::

            protoc --descriptor_set_out=api.desc --include_imports api.proto

        Args:
            path: Path to the ``.desc`` file.
            message_type: Fully qualified message type name (e.g. ``mypackage.MyMessage``).
        """
        self._load_from_bytes(Path(path).read_bytes(), message_type)
        _log.debug("Loaded schema for %s from %s", message_type, path)

    def load_schema(self, path: str | Path, message_type: str) -> None:
        """Load a ``.proto`` source (compiled via :func:`compile_proto`) or a ``.desc`` set.

        Raises:
            SchemaError: the ``.proto`` file could not be compiled.
        """
        if str(path).lower().endswith(_PROTO_SUFFIX):
            self._load_from_bytes(compile_proto(path), message_type)
        else:
            self.load_descriptor(path, message_type)

    def load_proto_from_descriptor_bytes(
        self, descriptor_bytes: bytes, message_type: str
    ) -> None:
        """Load from raw FileDescriptorSet bytes (for programmatic use)."""
        self._load_from_bytes(descriptor_bytes, message_type)

    def _load_from_bytes(self, raw: bytes, message_type: str) -> None:
        """Parse a FileDescriptorSet and select the given message type."""
        from google.protobuf import descriptor_pb2
        from google.protobuf.message_factory import MessageFactory

        desc_set = descriptor_pb2.FileDescriptorSet()
        desc_set.ParseFromString(raw)

        for file_proto in desc_set.file:
            try:
                self._pool.Add(file_proto)
            except TypeError:
                # Already added
                pass

        desc = self._pool.FindMessageTypeByName(message_type)
        self._message_class = _message_class_for(desc, MessageFactory(pool=self._pool))
        self._message_type_name = message_type
        self._loaded_types = self._collect_message_types(desc_set)

    def _collect_message_types(self, desc_set: Any) -> list[str]:
        """Collect all message type names from a FileDescriptorSet."""
        types: list[str] = []
        for file_proto in desc_set.file:
            package = file_proto.package
            for msg in file_proto.message_type:
                fqn = f"{package}.{msg.name}" if package else msg.name
                types.append(fqn)
                self._collect_nested_types(msg, fqn, types)
        return sorted(types)

    def _collect_nested_types(self, msg: Any, prefix: str, types: list[str]) -> None:
        """Recursively collect nested message types."""
        for nested in msg.nested_type:
            fqn = f"{prefix}.{nested.name}"
            types.append(fqn)
            self._collect_nested_types(nested, fqn, types)

    def list_message_types(self) -> list[str]:
        """Return all message type names available after loading a descriptor."""
        return list(self._loaded_types)

    def decode_text(self, data: bytes) -> str:
        """Decode *data* and render it in protobuf text format.

        Fields the schema does not know are printed by number, so nothing in
        the payload is hidden. Raises like :meth:`decode`.
        """
        from google.protobuf import text_format

        msg = self._parse(data)
        return text_format.MessageToString(msg, print_unknown_fields=True)

    def _parse(self, data: bytes) -> Any:
        """Parse *data* into a new instance of the loaded message class."""
        if self._message_class is None:
            raise RuntimeError(
                "No schema loaded. Call load_descriptor() or "
                "load_proto_from_descriptor_bytes() first."
            )
        msg = self._message_class()
        msg.ParseFromString(data)
        return msg

    def decode(self, data: bytes) -> dict[str, Any]:
        """Decode *data* using the loaded schema.

        Args:
            data: Raw protobuf bytes.

        Returns:
            Dictionary representation of the decoded message.

        Raises:
            RuntimeError: If no schema has been loaded.
            google.protobuf.message.DecodeError: If the data is malformed.
        """
        from google.protobuf.json_format import MessageToDict

        msg = self._parse(data)
        return MessageToDict(msg, preserving_proto_field_name=True)

    @property
    def available(self) -> bool:
        """``True`` if google-protobuf is installed."""
        try:
            import google.protobuf  # noqa: F401
            return True
        except ImportError:
            return False

    @property
    def message_type_name(self) -> str:
        """The currently selected message type name, or empty string."""
        return self._message_type_name


def _message_class_for(desc: Any, factory: Any) -> Any:
    """Concrete message class for *desc* across protobuf versions.

    ``message_factory.GetMessageClass`` replaced
    ``MessageFactory.GetPrototype``, which newer releases removed.
    """
    from google.protobuf import message_factory

    get_message_class = getattr(message_factory, "GetMessageClass", None)
    if get_message_class is not None:
        return get_message_class(desc)
    return factory.GetPrototype(desc)
