#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TUI screen modules."""

__all__ = ["MainScreen"]

try:
    from .main_screen import MainScreen
    SCREENS_AVAILABLE = True
except ImportError:
    SCREENS_AVAILABLE = False
