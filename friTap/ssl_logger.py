#!/usr/bin/env python3

"""Backward-compatibility shim. New code should use CoreController + Session.

    from friTap import CoreController, Session, FriTapConfig  # recommended
    from friTap import SSL_Logger  # legacy (delegates to friTap.legacy)
"""
# Re-exported because tests patch ``friTap.ssl_logger.frida.X`` and ``.logging``.
import logging

import frida

from .constants import SSL_READ, SSL_WRITE, ContentType
from .legacy.ssl_logger_core import SSL_Logger, _PluginSessionShim, get_addr_string

__all__ = ["SSL_Logger", "SSL_READ", "SSL_WRITE", "ContentType", "get_addr_string", "_PluginSessionShim", "frida", "logging"]
