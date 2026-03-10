#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Legacy compatibility module for friTap.

Contains extracted inline output logic from ssl_logger.py that is
preserved for backward compatibility when output handlers are not active.
"""

from .ssl_logger_core import SSL_Logger as SSL_Logger, get_addr_string as get_addr_string
from .session_manager import SessionManager as SessionManager
