"""Pydantic schemas for friTap message types.

Re-exports agent message models and canonical pipeline events for
convenient top-level access. Exports are resolved lazily (PEP 562) so the
dependency-free ``canonical`` module can be imported without pydantic.
"""

import importlib

# Exported name -> defining submodule. Resolved lazily (PEP 562) so importing a
# dependency-free submodule such as ``friTap.schemas.canonical`` (used by the
# offline CLI via ``friTap.pipeline``) no longer pulls in pydantic through
# ``agent_messages`` / ``host_messages``.
_AGENT_MESSAGE_NAMES = (
    "AgentMessage",
    "BaseAgentMessage",
    "CallerFrame",
    "CallerStackMessage",
    "ConsoleDebugMessage",
    "ConsoleDevMessage",
    "ConsoleErrorMessage",
    "ConsoleInfoMessage",
    "ConsoleMessage",
    "ConsoleWarnMessage",
    "DatalogMessage",
    "IPSecChildSAKeysMessage",
    "IPSecIKEKeysMessage",
    "IPSecESPKeysMessage",
    "KeylogMessage",
    "LibraryDetectedMessage",
    "NetlogMessage",
    "SSHKeyMessage",
    "SSHNewKeysMessage",
)
_CANONICAL_NAMES = (
    "AddressFamily",
    "DataCanonical",
    "Direction",
    "Endpoint",
    "KeylogCanonical",
    "MetaCanonical",
)
_HOST_MESSAGE_NAMES = (
    "AgentHandshakeConfig",
    "OffsetConfig",
    "PatternConfig",
    "RuntimeCommand",
    "ScriptInjection",
)
_LAZY_EXPORTS = {
    **{name: "agent_messages" for name in _AGENT_MESSAGE_NAMES},
    **{name: "canonical" for name in _CANONICAL_NAMES},
    **{name: "host_messages" for name in _HOST_MESSAGE_NAMES},
}

__all__ = [
    # Discriminated union
    "AgentMessage",
    # Base
    "BaseAgentMessage",
    # TLS
    "KeylogMessage",
    "DatalogMessage",
    # Library detection
    "LibraryDetectedMessage",
    # Console
    "ConsoleMessage",
    "ConsoleDevMessage",
    "ConsoleDebugMessage",
    "ConsoleInfoMessage",
    "ConsoleWarnMessage",
    "ConsoleErrorMessage",
    # Network
    "NetlogMessage",
    # SSH
    "SSHKeyMessage",
    "SSHNewKeysMessage",
    # IPSec
    "IPSecChildSAKeysMessage",
    "IPSecIKEKeysMessage",
    "IPSecESPKeysMessage",
    # SDK / caller attribution (opt-in)
    "CallerStackMessage",
    "CallerFrame",
    # Canonical pipeline events
    "Direction",
    "AddressFamily",
    "Endpoint",
    "KeylogCanonical",
    "DataCanonical",
    "MetaCanonical",
    # Host messages
    "AgentHandshakeConfig",
    "PatternConfig",
    "OffsetConfig",
    "ScriptInjection",
    "RuntimeCommand",
]


def __getattr__(name: str):
    """Import an exported name's submodule on first access (PEP 562)."""
    module_name = _LAZY_EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(importlib.import_module(f".{module_name}", __name__), name)
    globals()[name] = value  # cache: later lookups skip __getattr__
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
