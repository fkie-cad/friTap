#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared I/O formatting utilities for output handlers and sinks."""

from __future__ import annotations

from typing import IO


try:
    from hexdump import hexdump as _hexdump
except ImportError:
    _hexdump = None


def format_hexdump(data: bytes) -> str:
    """Format bytes as hexdump, with fallback if hexdump module unavailable."""
    if _hexdump is not None:
        return _hexdump(data, result='return')
    return data.hex()


def format_data_header(direction: str, src_addr: str, src_port: int,
                       dst_addr: str, dst_port: int) -> str:
    """Format the '[direction] src:port -> dst:port' header line."""
    return f"[{direction}] {src_addr}:{src_port} -> {dst_addr}:{dst_port}"


def write_keylog_line(fh: IO, key_data: str) -> None:
    """Write a keylog line and flush."""
    fh.write(key_data + "\n")
    fh.flush()
