#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CustomProtocolPlugin — base class for user-defined protocol plugins.

Extends ScriptPlugin with utility methods for the two core use cases:
  1. Key extraction — hook a function, read key material from args or return values
  2. Data capture — hook read/write functions to capture plaintext

Users subclass this, override setup_hooks(), and call hook_*() methods to
define their hooks. friTap handles module watching, JS generation, EventBus
integration, output routing, and PCAP capture automatically.
"""

from __future__ import annotations

import logging
import re
from abc import abstractmethod
from typing import Any, Dict, List, Optional, Union, TYPE_CHECKING

from ..events import KeylogEvent, DatalogEvent, ConsoleEvent, ErrorEvent
from .script_plugin import ScriptPlugin

if TYPE_CHECKING:
    from .script_context import ScriptContext
    from ..session import Session

logger = logging.getLogger("friTap.plugins.custom_protocol")


class HookDefinition:
    """Internal representation of a single hook definition."""

    __slots__ = (
        "hook_type", "symbol", "pattern", "offset",
        "arg", "byte_offset", "size", "label", "encoding",
        "data_arg", "length_arg", "direction",
        "on_enter_js", "on_leave_js",
    )

    def __init__(self, hook_type: str, **kwargs: Any) -> None:
        self.hook_type = hook_type
        self.symbol: Optional[str] = kwargs.get("symbol")
        self.pattern: Optional[Dict[str, List[str]]] = kwargs.get("pattern")
        self.offset: Optional[str] = kwargs.get("offset")
        self.arg: int = kwargs.get("arg", 0)
        self.byte_offset: Union[int, Dict[str, int]] = kwargs.get("byte_offset", 0)
        self.size: int = kwargs.get("size", 32)
        self.label: str = kwargs.get("label", "KEY")
        self.encoding: str = kwargs.get("encoding", "hex")
        self.data_arg: int = kwargs.get("data_arg", 0)
        self.length_arg: int = kwargs.get("length_arg", 1)
        self.direction: str = kwargs.get("direction", "read")
        self.on_enter_js: Optional[str] = kwargs.get("on_enter_js")
        self.on_leave_js: Optional[str] = kwargs.get("on_leave_js")

    # Attributes that must always be present per hook type, even when zero/empty
    _REQUIRED_ATTRS: Dict[str, tuple] = {
        "key_on_enter": ("arg", "byte_offset", "size", "label", "encoding"),
        "key_on_leave": ("arg", "byte_offset", "size", "label", "encoding"),
        "data_read": ("data_arg", "length_arg", "direction"),
        "data_write": ("data_arg", "length_arg", "direction"),
    }

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a dict for the JS code generator."""
        result: Dict[str, Any] = {"hook_type": self.hook_type}
        required = self._REQUIRED_ATTRS.get(self.hook_type, ())
        for attr in self.__slots__:
            if attr == "hook_type":
                continue
            val = getattr(self, attr)
            if attr in required or (val is not None and val != 0 and val != ""):
                result[attr] = val
        return result


class CustomProtocolPlugin(ScriptPlugin):
    """Abstract base for user-defined protocol plugins.

    Subclasses **must** define:
        - ``name`` — protocol identifier (e.g., "wireguard")
        - ``version`` — plugin version (e.g., "1.0.0")
        - ``display_name`` — human-readable name (e.g., "WireGuard VPN")
        - ``library_patterns`` — regex patterns for target library detection
        - ``setup_hooks()`` — define hooks via utility methods

    Subclasses **may** override:
        - ``platforms`` — restrict to specific platforms
        - ``architectures`` — restrict to specific architectures
        - ``format_template`` — key output format
        - ``wireshark_preference`` — Wireshark preference path
        - ``pcap_dlt`` — PCAP data link type
    """

    # --- Required (override in subclass) ---
    display_name: str = ""
    library_patterns: List[str] = []

    # --- Optional: platform & architecture targeting ---
    platforms: List[str] = []          # Empty = all platforms
    architectures: List[str] = []      # Empty = all architectures

    # --- Optional: output formatting ---
    format_template: str = "{label} {secret}"
    wireshark_preference: str = ""
    pcap_dlt: int = 1  # DLT_EN10MB

    def __init__(self) -> None:
        super().__init__()
        self._hook_defs: List[HookDefinition] = []
        self._session: Optional["Session"] = None

    # ------------------------------------------------------------------
    # ScriptPlugin overrides
    # ------------------------------------------------------------------

    @property
    def supported_backends(self) -> List[str]:
        return ["frida"]

    @property
    def description(self) -> str:
        return f"Custom protocol plugin: {self.display_name}"

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_load(self, session: "Session") -> None:
        """Auto-register protocol handler in the ProtocolRegistry."""
        self._session = session
        self._register_protocol_handler()
        logger.info(
            "Custom protocol plugin loaded: %s (%s)", self.name, self.display_name,
        )

    def on_instrument(self, context: "ScriptContext") -> None:
        """Generate JS from hook definitions and inject it."""
        self._hook_defs.clear()

        # Let the user define hooks
        self.setup_hooks()

        if not self._hook_defs:
            logger.warning("Plugin %s: setup_hooks() defined no hooks", self.name)
            return

        # Delegate to parent for script creation + loading
        super().on_instrument(context)

    def get_script_source(self, context: "ScriptContext") -> str:
        """Generate Frida JS from accumulated hook definitions."""
        from .js_codegen import generate_js

        return generate_js(
            hook_defs=[h.to_dict() for h in self._hook_defs],
            library_patterns=self.library_patterns,
            protocol_name=self.name,
            platforms=self.platforms,
            architectures=self.architectures,
            debug=context.debug_output,
        )

    def on_script_message(self, message: dict, data: Any) -> None:
        """Route messages from generated JS to the EventBus."""
        if message.get("type") == "error":
            logger.error("Plugin %s script error: %s", self.name, message)
            self._emit_error(
                message.get("description", "Unknown script error"),
                message.get("stack", ""),
            )
            return

        payload = message.get("payload")
        if not isinstance(payload, dict):
            logger.debug("Plugin %s: non-dict payload: %s", self.name, message)
            return

        content_type = payload.get("contentType", "")

        if content_type == "keylog":
            self.emit_key(payload.get("label", "KEY"), payload.get("data", ""))
        elif content_type == "datalog":
            direction = payload.get("direction", "read")
            raw_data = data if data else b""
            self.emit_data(raw_data, direction, payload.get("function", ""))
        elif content_type == "console":
            self.log(payload.get("message", ""))
        elif content_type == "devlog":
            logger.debug("Plugin %s [devlog]: %s", self.name, payload.get("message", ""))

    # ------------------------------------------------------------------
    # Abstract: user defines hooks here
    # ------------------------------------------------------------------

    @abstractmethod
    def setup_hooks(self) -> None:
        """Define hooks by calling hook_*() utility methods.

        Called during on_instrument(). Example::

            def setup_hooks(self):
                self.hook_key_on_enter(
                    symbol="my_key_init",
                    arg=0, size=32,
                    label="AES_KEY"
                )
        """
        ...

    # ------------------------------------------------------------------
    # Hook definition utility methods
    # ------------------------------------------------------------------

    def hook_key_on_enter(
        self,
        *,
        symbol: Optional[str] = None,
        pattern: Optional[Dict[str, List[str]]] = None,
        offset: Optional[str] = None,
        arg: int = 0,
        byte_offset: Union[int, Dict[str, int]] = 0,
        size: int = 32,
        label: str = "KEY",
        encoding: str = "hex",
    ) -> None:
        """Extract key material from a function argument on entry.

        Resolution order: symbol -> pattern -> offset (first match wins).
        """
        self._add_key_hook(
            "key_on_enter", symbol=symbol, pattern=pattern, offset=offset,
            arg=arg, byte_offset=byte_offset, size=size,
            label=label, encoding=encoding,
        )

    def hook_key_on_leave(
        self,
        *,
        symbol: Optional[str] = None,
        pattern: Optional[Dict[str, List[str]]] = None,
        offset: Optional[str] = None,
        byte_offset: Union[int, Dict[str, int]] = 0,
        size: int = 32,
        label: str = "KEY",
        encoding: str = "hex",
    ) -> None:
        """Extract key material from return value after function completes."""
        self._add_key_hook(
            "key_on_leave", symbol=symbol, pattern=pattern, offset=offset,
            byte_offset=byte_offset, size=size,
            label=label, encoding=encoding,
        )

    def hook_read(
        self,
        *,
        symbol: Optional[str] = None,
        pattern: Optional[Dict[str, List[str]]] = None,
        offset: Optional[str] = None,
        data_arg: int = 0,
        length_arg: int = 1,
    ) -> None:
        """Capture plaintext data from a read/decrypt function."""
        self._add_data_hook(
            "read", symbol=symbol, pattern=pattern, offset=offset,
            data_arg=data_arg, length_arg=length_arg,
        )

    def hook_write(
        self,
        *,
        symbol: Optional[str] = None,
        pattern: Optional[Dict[str, List[str]]] = None,
        offset: Optional[str] = None,
        data_arg: int = 0,
        length_arg: int = 1,
    ) -> None:
        """Capture plaintext data from a write/encrypt function."""
        self._add_data_hook(
            "write", symbol=symbol, pattern=pattern, offset=offset,
            data_arg=data_arg, length_arg=length_arg,
        )

    def hook_function(
        self,
        *,
        symbol: Optional[str] = None,
        pattern: Optional[Dict[str, List[str]]] = None,
        offset: Optional[str] = None,
        on_enter_js: Optional[str] = None,
        on_leave_js: Optional[str] = None,
    ) -> None:
        """Low-level hook with custom JS callback snippets.

        The JS snippets have access to: args (on_enter), retval (on_leave),
        sendKey(label, bytes), sendData(bytes, direction), and all Frida APIs.
        """
        self._validate_hook_target(symbol, pattern, offset)
        if on_enter_js is None and on_leave_js is None:
            raise ValueError("hook_function() requires at least on_enter_js or on_leave_js")
        self._hook_defs.append(HookDefinition(
            "custom",
            symbol=symbol, pattern=pattern, offset=offset,
            on_enter_js=on_enter_js, on_leave_js=on_leave_js,
        ))

    # ------------------------------------------------------------------
    # Python-side convenience methods
    # ------------------------------------------------------------------

    def emit_key(self, label: str, key_hex: str) -> None:
        """Manually emit a KeylogEvent."""
        if self._session is None:
            logger.warning("Plugin %s: emit_key called before on_load", self.name)
            return
        formatted = self.format_template.format(label=label, secret=key_hex, secret_base64=key_hex)
        self._session.lifecycle_bus.emit(KeylogEvent(
            key_data=formatted,
            protocol=self.name,
        ))

    def emit_data(self, data_bytes: bytes, direction: str, function: str = "") -> None:
        """Manually emit a DatalogEvent."""
        if self._session is None:
            logger.warning("Plugin %s: emit_data called before on_load", self.name)
            return
        self._session.lifecycle_bus.emit(DatalogEvent(
            data=data_bytes,
            direction=direction,
            function=function or f"{self.name}_{direction}",
            protocol=self.name,
        ))

    def log(self, message: str) -> None:
        """Emit a ConsoleEvent."""
        if self._session is None:
            logger.info("Plugin %s: %s", self.name, message)
            return
        self._session.lifecycle_bus.emit(ConsoleEvent(
            message=f"[{self.display_name}] {message}",
            protocol=self.name,
        ))

    # ------------------------------------------------------------------
    # Protocol handler auto-registration
    # ------------------------------------------------------------------

    def _register_protocol_handler(self) -> None:
        """Create and register a TemplateProtocolHandler in the global registry."""
        try:
            from ..protocols.registry import ProtocolRegistry  # noqa: F401
            from ..protocols.base import ProtocolHandler

            plugin = self
            compiled_patterns = [re.compile(pat, re.IGNORECASE) for pat in self.library_patterns]

            class TemplateProtocolHandler(ProtocolHandler):
                """Auto-generated protocol handler for a CustomProtocolPlugin."""

                @property
                def name(self) -> str:
                    return plugin.name

                @property
                def display_name(self) -> str:
                    return plugin.display_name

                def get_keylog_format(self) -> str:
                    return f"{plugin.display_name} Key Log"

                def format_key_for_wireshark(self, key_data: str) -> str:
                    return key_data

                def get_wireshark_protocol_preference(self) -> str:
                    return plugin.wireshark_preference

                def get_pcap_dlt(self) -> int:
                    return plugin.pcap_dlt

                def matches_libraries(self, detected_libraries: List[str]) -> bool:
                    for lib in detected_libraries:
                        for pat in compiled_patterns:
                            if pat.match(lib):
                                return True
                    return False

            self._protocol_handler = TemplateProtocolHandler()
            logger.debug(
                "Created TemplateProtocolHandler for %s", self.name,
            )
        except ImportError:
            logger.debug("ProtocolRegistry not available — skipping registration")

    def get_protocol_handler(self) -> Optional[Any]:
        """Return the auto-generated protocol handler, if available."""
        return getattr(self, "_protocol_handler", None)

    # ------------------------------------------------------------------
    # Private hook accumulation helpers
    # ------------------------------------------------------------------

    def _add_key_hook(
        self, phase: str, **kwargs: Any,
    ) -> None:
        """Shared logic for hook_key_on_enter / hook_key_on_leave."""
        self._validate_hook_target(kwargs.get("symbol"), kwargs.get("pattern"), kwargs.get("offset"))
        self._validate_size(kwargs.get("size", 32))
        self._hook_defs.append(HookDefinition(phase, **kwargs))

    def _add_data_hook(
        self, direction: str, **kwargs: Any,
    ) -> None:
        """Shared logic for hook_read / hook_write."""
        self._validate_hook_target(kwargs.get("symbol"), kwargs.get("pattern"), kwargs.get("offset"))
        self._hook_defs.append(HookDefinition(
            f"data_{direction}", direction=direction, **kwargs,
        ))

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_hook_target(
        symbol: Optional[str],
        pattern: Optional[Dict[str, List[str]]],
        offset: Optional[str],
    ) -> None:
        """Ensure at least one resolution target is provided."""
        if symbol is None and pattern is None and offset is None:
            raise ValueError(
                "At least one of symbol, pattern, or offset must be provided"
            )

    @staticmethod
    def _validate_size(size: int) -> None:
        """Ensure size is within bounds."""
        if size <= 0 or size > 4096:
            raise ValueError(f"size must be between 1 and 4096, got {size}")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _emit_error(self, description: str, stack: str = "") -> None:
        """Emit an ErrorEvent."""
        if self._session is None:
            return
        self._session.lifecycle_bus.emit(ErrorEvent(
            error=f"Plugin {self.name} error",
            description=description,
            stack=stack,
            protocol=self.name,
        ))
