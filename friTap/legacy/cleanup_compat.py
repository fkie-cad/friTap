#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Legacy cleanup logic for non-handler path.

Used when output handlers are not active (_handlers_active is False).
"""

import os


def cleanup_legacy(logger_instance):
    """Legacy cleanup logic extracted from ssl_logger.py cleanup().

    Args:
        logger_instance: The SSL_Logger instance (self)
    """
    if logger_instance.live:
        try:
            os.unlink(logger_instance.filename)
            os.rmdir(logger_instance.tmpdir)
        except OSError:
            pass

    # Finalize JSON output if enabled
    if logger_instance.json_output:
        logger_instance._finalize_json_output()
