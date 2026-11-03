#!/usr/bin/env python3

"""Output handler abstraction for friTap.

The handler classes are exported lazily (PEP 562 module ``__getattr__``).
Importing any submodule runs this ``__init__`` first, and the light
:mod:`friTap.output.keylog_format` validators are imported by protocol,
plugin and offline code. Importing every handler eagerly here would pull in
``pcapng_handler`` -> :mod:`friTap.sinks` -> :mod:`friTap.schemas` -> pydantic
on every ``--analyze`` / offline run. Each name below is imported from its
submodule on first access instead, so ``from friTap.output import X`` keeps
working for every exported name.
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

# Exported name -> submodule (relative to this package) that defines it.
_LAZY_EXPORTS: dict[str, str] = {
    "OutputHandler": "base",
    "PcapOutputHandler": "pcap_handler",
    "KeylogOutputHandler": "keylog_handler",
    "KeylogFormatter": "keylog_format",
    "JsonOutputHandler": "json_handler",
    "JsonlOutputHandler": "jsonl_handler",
    "ConsoleOutputHandler": "console_handler",
    "LiveWiresharkHandler": "live_wireshark_handler",
    "PcapngOutputHandler": "pcapng_handler",
    "LivePcapngHandler": "live_pcapng_handler",
    "LiveAutoDecryptHandler": "live_autodecrypt_handler",
    "KeyCollectorHandler": "key_collector_handler",
    "OutputHandlerFactory": "factory",
}

__all__ = [
    "OutputHandler",
    "PcapOutputHandler",
    "KeylogOutputHandler",
    "KeylogFormatter",
    "JsonOutputHandler",
    "JsonlOutputHandler",
    "ConsoleOutputHandler",
    "LiveWiresharkHandler",
    "PcapngOutputHandler",
    "LivePcapngHandler",
    "LiveAutoDecryptHandler",
    "KeyCollectorHandler",
    "OutputHandlerFactory",
]

if TYPE_CHECKING:  # static analysers and IDEs see the real names
    from .base import OutputHandler
    from .console_handler import ConsoleOutputHandler
    from .factory import OutputHandlerFactory
    from .json_handler import JsonOutputHandler
    from .jsonl_handler import JsonlOutputHandler
    from .key_collector_handler import KeyCollectorHandler
    from .keylog_format import KeylogFormatter
    from .keylog_handler import KeylogOutputHandler
    from .live_autodecrypt_handler import LiveAutoDecryptHandler
    from .live_pcapng_handler import LivePcapngHandler
    from .live_wireshark_handler import LiveWiresharkHandler
    from .pcap_handler import PcapOutputHandler
    from .pcapng_handler import PcapngOutputHandler


def __getattr__(name: str):
    """Import an exported handler on first access and cache it here."""
    submodule = _LAZY_EXPORTS.get(name)
    if submodule is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(f".{submodule}", __name__), name)
    globals()[name] = value  # later lookups bypass __getattr__
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
