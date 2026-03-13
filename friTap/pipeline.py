#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Message processing pipeline for friTap.

Using predefined data-path events (keylog, datalog) with a
deterministic linear pipeline. Lifecycle events (library detection,
session state, errors) still use the per-session EventBus.

Stages (current):
    1. Validate      - Schema check (cold: full; hot: contentType only)
    2. Normalize     - Raw addresses -> strings, function -> Direction
    3. Canonicalize  - Produce frozen KeylogCanonical / DataCanonical

Fan-out to sinks is handled by MessagePipeline.push() after stages complete.
"""

from __future__ import annotations
import logging
import socket
import struct
import time
from typing import Protocol as TypingProtocol, TYPE_CHECKING, runtime_checkable

from .schemas.canonical import (
    AddressFamily,
    DataCanonical,
    Direction,
    Endpoint,
    KeylogCanonical,
    MetaCanonical,
)

from .constants import SSL_READ

if TYPE_CHECKING:
    from .sinks.base import Sink

logger = logging.getLogger("friTap.pipeline")


@runtime_checkable
class PipelineStage(TypingProtocol):
    """Protocol for a pipeline processing stage."""

    def process(self, msg: dict, data: bytes | None, ctx: PipelineContext) -> dict | None:
        """Process a message. Return None to drop, return msg to continue."""
        ...


class PipelineContext:
    """Mutable context passed through pipeline stages."""

    __slots__ = (
        "timestamp", "direction", "src", "dst", "ss_family",
        "connection_id", "protocol", "ssl_session_id",
        "src_addr_raw", "dst_addr_raw", "canonical",
    )

    def __init__(self) -> None:
        self.timestamp: float = 0.0
        self.direction: Direction | None = None
        self.src: Endpoint | None = None
        self.dst: Endpoint | None = None
        self.ss_family: AddressFamily = AddressFamily.AF_INET
        self.connection_id: str = ""
        self.protocol: str = "tls"
        self.ssl_session_id: str = ""
        self.src_addr_raw: int | str = 0
        self.dst_addr_raw: int | str = 0
        self.canonical: KeylogCanonical | DataCanonical | MetaCanonical | None = None


class ValidateStage:
    """Stage 1: Validate contentType field exists."""

    def __init__(self, debug: bool = False) -> None:
        self._debug = debug
        self._adapter = None
        if debug:
            from pydantic import TypeAdapter
            from .schemas.agent_messages import AgentMessage
            self._adapter = TypeAdapter(AgentMessage)

    def process(self, msg: dict, data: bytes | None, ctx: PipelineContext) -> dict | None:
        content_type = msg.get("contentType")
        if not content_type:
            logger.warning("Message missing contentType, dropping: %s", msg)
            return None
        if self._adapter is not None:
            try:
                self._adapter.validate_python(msg)
            except Exception as e:
                logger.debug("Validation warning (non-blocking): %s", e)
        return msg


class DeduplicateStage:
    """Stage 1.5: Drop duplicate keylog entries."""

    def __init__(self) -> None:
        self._seen_keys: set[str] = set()

    def process(self, msg: dict, data: bytes | None, ctx: PipelineContext) -> dict | None:
        if msg.get("contentType") != "keylog":
            return msg
        keylog = msg.get("keylog", "")
        if keylog in self._seen_keys:
            return None
        self._seen_keys.add(keylog)
        return msg


class NormalizeStage:
    """Stage 2: Normalize addresses and derive direction."""

    # Names of read/write functions for direction detection
    READ_FUNCTIONS = SSL_READ

    def process(self, msg: dict, data: bytes | None, ctx: PipelineContext) -> dict | None:
        ctx.timestamp = time.time()
        ctx.protocol = msg.get("protocol", "tls")

        content_type = msg.get("contentType")
        if content_type == "datalog":
            self._normalize_datalog(msg, ctx)
        elif content_type == "keylog":
            ctx.ssl_session_id = ""

        return msg

    def _normalize_datalog(self, msg: dict, ctx: PipelineContext) -> None:
        ss_family = msg.get("ss_family", "AF_INET")
        try:
            ctx.ss_family = AddressFamily(ss_family)
        except ValueError:
            ctx.ss_family = AddressFamily.AF_INET

        src_raw = msg.get("src_addr", 0)
        dst_raw = msg.get("dst_addr", 0)
        ctx.src_addr_raw = src_raw
        ctx.dst_addr_raw = dst_raw

        ctx.src = Endpoint(
            addr=self._addr_to_string(src_raw, ss_family),
            port=msg.get("src_port", 0),
        )
        ctx.dst = Endpoint(
            addr=self._addr_to_string(dst_raw, ss_family),
            port=msg.get("dst_port", 0),
        )

        function = msg.get("function", "")
        ctx.direction = Direction.READ if function in self.READ_FUNCTIONS else Direction.WRITE
        ctx.ssl_session_id = str(msg.get("ssl_session_id", ""))

    @staticmethod
    def _addr_to_string(addr: int | str, ss_family: str) -> str:
        """Convert raw address to string representation."""
        if isinstance(addr, str):
            if ss_family == "AF_INET6" and len(addr) == 32:
                # IPv6 hex string -> proper notation
                try:
                    return socket.inet_ntop(
                        socket.AF_INET6, bytes.fromhex(addr)
                    )
                except (ValueError, OSError):
                    return addr
            return addr
        if ss_family == "AF_INET6":
            return str(addr)
        # IPv4: convert integer to dotted notation
        if isinstance(addr, int) and addr > 0:
            try:
                return socket.inet_ntoa(struct.pack("!I", addr))
            except (struct.error, OSError):
                return str(addr)
        return str(addr)


class CanonicalizeStage:
    """Stage 3: Produce frozen canonical events."""

    def process(self, msg: dict, data: bytes | None, ctx: PipelineContext) -> dict | None:
        content_type = msg.get("contentType")

        if content_type == "keylog":
            ctx.canonical = KeylogCanonical(
                key_data=msg.get("keylog", ""),
                protocol=ctx.protocol,
                timestamp=ctx.timestamp,
            )
        elif content_type == "datalog" and data:
            ctx.canonical = DataCanonical(
                data=data,
                direction=ctx.direction or Direction.READ,
                src=ctx.src or Endpoint("", 0),
                dst=ctx.dst or Endpoint("", 0),
                ss_family=ctx.ss_family,
                ssl_session_id=ctx.ssl_session_id,
                protocol=ctx.protocol,
                timestamp=ctx.timestamp,
                connection_id=ctx.connection_id,
                src_addr_raw=ctx.src_addr_raw,
                dst_addr_raw=ctx.dst_addr_raw,
            )
        elif content_type in ("console", "console_dev", "console_debug",
                               "console_info", "console_warn", "console_error"):
            text = msg.get("console", "") or msg.get("console_dev", "") or msg.get("message", "")
            ctx.canonical = MetaCanonical(
                event_type="console",
                message=text,
                level=msg.get("level", "info"),
                protocol=ctx.protocol,
                timestamp=ctx.timestamp,
            )
        elif content_type == "library_detected":
            ctx.canonical = MetaCanonical(
                event_type="library_detected",
                message=msg.get("message", ""),
                library=msg.get("library", ""),
                protocol=ctx.protocol,
                timestamp=ctx.timestamp,
            )

        return msg


class MessagePipeline:
    """Linear message processing pipeline with fan-out to sinks.

    Usage:
        pipeline = MessagePipeline()
        pipeline.add_stage(ValidateStage())
        pipeline.add_stage(NormalizeStage())
        pipeline.add_stage(CanonicalizeStage())
        pipeline.add_sink(my_sink)
        pipeline.push({"contentType": "keylog", "keylog": "CLIENT_RANDOM ..."})
    """

    def __init__(self) -> None:
        self._stages: list[PipelineStage] = []
        self._sinks: list[Sink] = []

    def add_stage(self, stage: PipelineStage) -> None:
        self._stages.append(stage)

    def add_sink(self, sink: "Sink") -> None:
        self._sinks.append(sink)

    def remove_sink(self, sink: "Sink") -> None:
        try:
            self._sinks.remove(sink)
        except ValueError:
            pass

    @property
    def sinks(self) -> list["Sink"]:
        return list(self._sinks)

    def push(self, msg: dict, data: bytes | None = None) -> None:
        """Push a message through the pipeline stages, then fan out to sinks."""
        ctx = PipelineContext()

        # Run through stages
        current = msg
        for stage in self._stages:
            result = stage.process(current, data, ctx)
            if result is None:
                return  # Message dropped
            current = result

        # Fan out canonical event to sinks
        canonical = ctx.canonical
        if canonical is None:
            return

        for sink in self._sinks:
            try:
                if isinstance(canonical, KeylogCanonical):
                    sink.on_keylog(canonical)
                elif isinstance(canonical, DataCanonical):
                    sink.on_data(canonical)
                elif isinstance(canonical, MetaCanonical):
                    sink.on_meta(canonical)
            except Exception:
                logger.exception("Sink %s failed", type(sink).__name__)

    def flush_all(self) -> None:
        """Flush all sinks."""
        for sink in self._sinks:
            try:
                sink.flush()
            except Exception:
                logger.exception("Flush failed for %s", type(sink).__name__)

    def close_all(self) -> None:
        """Close all sinks."""
        for sink in self._sinks:
            try:
                sink.close()
            except Exception:
                logger.exception("Close failed for %s", type(sink).__name__)


def create_default_pipeline(debug: bool = False) -> MessagePipeline:
    """Create a pipeline with the default stage ordering."""
    pipeline = MessagePipeline()
    pipeline.add_stage(ValidateStage(debug=debug))
    pipeline.add_stage(DeduplicateStage())
    pipeline.add_stage(NormalizeStage())
    pipeline.add_stage(CanonicalizeStage())
    return pipeline
