"""Concurrent first lookups of a lazily pinned transport (process-global registry)."""

import threading

from friTap.offline.mtproto import tl_parser
from friTap.parsers.registry import ParserRegistry

_THREADS = 16


def test_concurrent_first_lookups_all_get_the_resolved_pin(monkeypatch):
    import importlib

    reg = ParserRegistry()
    reg.pin_transport_lazy("mtproto", "friTap.offline.mtproto.tl_parser:MtprotoParser")
    barrier = threading.Barrier(_THREADS)
    real_import = importlib.import_module

    def slow_import(name, *args, **kwargs):
        threading.Event().wait(0.05)  # widen the resolve window
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(importlib, "import_module", slow_import)
    results, errors = [], []

    def lookup():
        barrier.wait()
        try:
            results.append(reg.pinned_parser_for("mtproto"))
        except Exception as exc:  # noqa: BLE001 - the race surfaced as KeyError
            errors.append(exc)

    threads = [threading.Thread(target=lookup) for _ in range(_THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert results == [tl_parser.MtprotoParser] * _THREADS
