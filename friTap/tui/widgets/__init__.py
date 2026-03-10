#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reusable TUI widgets for friTap."""

try:
    from .activity_log import ActivityLog  # noqa: F401
    from .status_bar import StatusBar  # noqa: F401
    from .menu_panel import MenuPanel  # noqa: F401
    WIDGETS_AVAILABLE = True
except ImportError:
    WIDGETS_AVAILABLE = False
