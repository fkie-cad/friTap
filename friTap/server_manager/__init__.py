#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Cross-platform frida-server management.

Provides a unified interface for downloading, deploying, starting, and
stopping frida-server on Android, iOS, Linux, macOS, and Windows targets.

Usage::

    from friTap.server_manager.factory import get_server_manager

    mgr = get_server_manager(device)   # auto-detect platform
    mgr.install(device)                # download + deploy
    mgr.start(device)                  # start frida-server
"""

from .base import BaseFridaServerManager, LocalUnixServerManager
from .factory import get_server_manager

__all__ = ["BaseFridaServerManager", "LocalUnixServerManager", "get_server_manager"]
