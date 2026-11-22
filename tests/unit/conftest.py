"""Shared fixtures for tests/unit."""

import logging

import pytest


class _RecordingHandler(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append(record)


@pytest.fixture
def fritap_log_records():
    """Attach a recording handler to a friTap logger: ``records = fritap_log_records(name)``.

    caplog sees nothing here because friTap's loggers do not propagate to root.
    The logger is set to DEBUG while attached; level and handler are restored after.
    """
    attached = []

    def attach(logger_name, level=logging.DEBUG):
        logger = logging.getLogger(logger_name)
        handler = _RecordingHandler()
        attached.append((logger, handler, logger.level))
        logger.addHandler(handler)
        logger.setLevel(level)
        return handler.records

    yield attach
    for logger, handler, old_level in reversed(attached):
        logger.removeHandler(handler)
        logger.setLevel(old_level)


@pytest.fixture(autouse=True)
def _isolated_learned_offsets_cache(tmp_path_factory, monkeypatch):
    """Keep SSL_Logger construction away from the developer's real learned-offsets cache."""
    monkeypatch.setenv("FRITAP_LEARNED_OFFSETS_DIR", str(tmp_path_factory.mktemp("learned_offsets")))


@pytest.fixture(autouse=True)
def _isolated_applovin_salt_cache(tmp_path_factory, monkeypatch):
    """Keep AppLovinKeyring.from_sources() away from the developer's real salt cache."""
    cache_dir = tmp_path_factory.mktemp("applovin_salt_cache")
    monkeypatch.setenv("FRITAP_APPLOVIN_SALT_CACHE", str(cache_dir / "applovin_salts.json"))
    monkeypatch.delenv("FRITAP_APPLOVIN_NO_CACHE", raising=False)


@pytest.fixture(autouse=True)
def _isolated_extension_discovery(monkeypatch):
    """Keep tests away from the developer's real UI extensions / offline decryptors.

    Discovery is disabled by default and the extension registry is reset around
    every test; tests that need discovery ``monkeypatch.delenv`` the switches.
    """
    from friTap import extensions

    monkeypatch.setenv("FRITAP_DISABLE_UI_EXTENSIONS", "1")
    monkeypatch.setenv("FRITAP_DISABLE_OFFLINE_DECRYPTOR_DISCOVERY", "1")
    extensions.reset_extensions()
    yield
    extensions.reset_extensions()
