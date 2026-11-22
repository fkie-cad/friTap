"""Pydantic schemas for friTap message types.

Re-exports agent message models and canonical pipeline events for
convenient top-level access. Exports are resolved lazily (PEP 562) so the
dependency-free ``canonical`` module can be imported without pydantic.
"""

import importlib

# Resolved lazily so importing the dependency-free ``friTap.schemas.canonical``
# (offline CLI via ``friTap.pipeline``) does not pull in pydantic.
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
    "RequestContextMessage",
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
    "AgentMessage",
    "BaseAgentMessage",
    "KeylogMessage",
    "DatalogMessage",
    "LibraryDetectedMessage",
    "ConsoleMessage",
    "ConsoleDevMessage",
    "ConsoleDebugMessage",
    "ConsoleInfoMessage",
    "ConsoleWarnMessage",
    "ConsoleErrorMessage",
    "NetlogMessage",
    "SSHKeyMessage",
    "SSHNewKeysMessage",
    "IPSecChildSAKeysMessage",
    "IPSecIKEKeysMessage",
    "IPSecESPKeysMessage",
    "CallerStackMessage",
    "CallerFrame",
    "RequestContextMessage",
    "Direction",
    "AddressFamily",
    "Endpoint",
    "KeylogCanonical",
    "DataCanonical",
    "MetaCanonical",
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
