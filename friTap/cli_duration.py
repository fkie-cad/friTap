"""The --duration timer: stop the capture after N seconds like Ctrl+C."""

import threading

from .cli_stream import _stop_signal_received


def _stop_capture_after_duration(ssl_log, seconds, logger):
    """Timer callback: end the capture via the same path as Ctrl+C."""
    logger.info(f"--duration {seconds:g}s elapsed; stopping the capture.")
    if not _capture_already_stopping(ssl_log):
        from .output.stdout_stream import ENDED_BY_DURATION, note_end_reason
        note_end_reason(ENDED_BY_DURATION)
    ssl_log.stop_capture_gracefully()


def _capture_already_stopping(ssl_log):
    """True when a teardown (stop signal, target exit) is already under way, so
    the --duration timer is not what ends the run."""
    return (getattr(ssl_log, "_cleanup_done", False)
            or getattr(ssl_log, "_session_end_claimed", False)
            or _stop_signal_received(ssl_log))


def _start_duration_timer(ssl_log, seconds, logger):
    """Arm a daemon timer that stops the capture after *seconds*.

    Returns the started timer, or None when no duration was requested."""
    if not seconds:
        return None
    timer = threading.Timer(seconds, _stop_capture_after_duration,
                            args=(ssl_log, seconds, logger))
    timer.name = "fritap-duration"
    timer.daemon = True
    timer.start()
    logger.info(f"Capture will stop automatically after {seconds:g}s (--duration).")
    return timer
