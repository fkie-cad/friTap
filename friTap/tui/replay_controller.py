#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Backward-compatibility shim.

``ReplayController`` and ``IFlowSource`` moved to :mod:`friTap.flow.replay`
(they are presentation-agnostic — they wrap :class:`TapReader` and have no TUI
dependency). This module re-exports them so existing imports such as
``from friTap.tui.replay_controller import ReplayController`` keep working.
"""

from __future__ import annotations

from friTap.flow.replay import IFlowSource, ReplayController, _LRUCache  # noqa: F401

__all__ = ["ReplayController", "IFlowSource", "_LRUCache"]
