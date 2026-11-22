#!/usr/bin/env python3

"""Cleanup for the non-handler path (``_handlers_active`` is False)."""

import os


def cleanup_legacy(logger_instance):
    """Remove the live-view pipe and finalize the JSON output."""
    if logger_instance.live:
        try:
            os.unlink(logger_instance.filename)
            os.rmdir(logger_instance.tmpdir)
        except OSError:
            pass

    if logger_instance.json_output:
        logger_instance._finalize_json_output()
