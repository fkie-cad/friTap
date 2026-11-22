#!/usr/bin/env python3

"""The non-handler (legacy) capture path: session manager and the SSL_Logger core."""

from .session_manager import SessionManager as SessionManager
from .ssl_logger_core import SSL_Logger as SSL_Logger
from .ssl_logger_core import get_addr_string as get_addr_string
