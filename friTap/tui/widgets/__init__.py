#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reusable TUI widgets for friTap."""

__all__ = ["ActivityLog", "StatusBar", "MenuPanel"]

try:
    from .activity_log import ActivityLog
    from .status_bar import StatusBar
    from .menu_panel import MenuPanel
    WIDGETS_AVAILABLE = True
except ImportError:
    WIDGETS_AVAILABLE = False
