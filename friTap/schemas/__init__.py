"""Pydantic schemas for friTap message types.

Re-exports agent message models and canonical pipeline events for
convenient top-level access.
"""

from .agent_messages import (
    AgentMessage,
    BaseAgentMessage,
    ConsoleDebugMessage,
    ConsoleDevMessage,
    ConsoleErrorMessage,
    ConsoleInfoMessage,
    ConsoleMessage,
    ConsoleWarnMessage,
    DatalogMessage,
    IPSecChildSAKeysMessage,
    IPSecIKEKeysMessage,
    KeylogMessage,
    LibraryDetectedMessage,
    NetlogMessage,
    SSHKeyMessage,
    SSHNewKeysMessage,
)

from .canonical import (
    AddressFamily,
    DataCanonical,
    Direction,
    Endpoint,
    KeylogCanonical,
    MetaCanonical,
)

from .host_messages import (
    AgentHandshakeConfig,
    OffsetConfig,
    PatternConfig,
    RuntimeCommand,
    ScriptInjection,
)

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
