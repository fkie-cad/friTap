#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Backward-compatibility shim. New code should use CoreController + Session.

    from friTap import CoreController, Session, FriTapConfig  # recommended
    from friTap import SSL_Logger  # legacy (delegates to friTap.legacy)
"""
from .constants import SSL_READ, SSL_WRITE, ContentType
from .legacy.ssl_logger_core import SSL_Logger, get_addr_string, _PluginSessionShim

__all__ = ["SSL_Logger", "SSL_READ", "SSL_WRITE", "ContentType", "get_addr_string", "_PluginSessionShim"]
