"""Build a :class:`friTap.api.FriTapSession` around an already-attached SSL_Logger."""

from __future__ import annotations

from friTap.api import FriTapSession
from friTap.backends.capture import create_legacy_capture_session
from friTap.config import FriTapConfig


def embedded_api_session(ssl_logger) -> FriTapSession:
    """A running embedded session the way ``FriTap.start()`` wires it, minus the attach.

    The test has already set the logger up as attached, so the coordinator's
    producer start must not attach again.
    """
    ssl_logger.start_fritap_session = lambda: None
    coordinator = create_legacy_capture_session(
        FriTapConfig(target="test_app"), ssl_logger, embedded=True,
    )
    coordinator.start()
    return FriTapSession(ssl_logger, ssl_logger._event_bus, coordinator=coordinator)
