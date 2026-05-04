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
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

_log = logging.getLogger(__name__)


def _check_protobuf_available() -> None:
    """Raise ImportError with a helpful message if google.protobuf is missing."""
    try:
        import google.protobuf  # noqa: F401
    except ImportError:
        raise ImportError(
            "Schema-based protobuf decoding requires the 'protobuf' package. "
            "Install it with: pip install protobuf>=3.20.0"
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
        from google.protobuf import descriptor_pool, descriptor_pb2
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
        factory = MessageFactory(pool=self._pool)
        self._message_class = factory.GetPrototype(desc)
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
        if self._message_class is None:
            raise RuntimeError(
                "No schema loaded. Call load_descriptor() or "
                "load_proto_from_descriptor_bytes() first."
            )
        from google.protobuf.json_format import MessageToDict

        msg = self._message_class()
        msg.ParseFromString(data)
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
