"""Regression tests for the Capture Results keylog rows (T6).

The results stats used to union the hook keylog and the memory-scan sidecars
into one count shown on the hook "Key log" row; in memory-scan-only mode the
tls sidecar IS the ``-k`` file, so it was listed twice; and ``if key_count:``
hid the ``0 keys`` an empty keylog used to show.
"""

from __future__ import annotations

import pytest

pytest.importorskip("textual")

from tests.unit.test_tui_decrypt_to_flow import _make_controller  # noqa: E402


def _write(path, *lines):
    path.write_text("".join(f"{line}\n" for line in lines))
    return str(path)


def _setup(tmp_path, hook_files, sidecars, base=None):
    controller, screen, pushed, state = _make_controller()
    state.keylog_path = base or next(iter(hook_files.values()), "")
    controller._resolve_keylog_files = lambda _base, _protos: dict(hook_files)
    controller._memory_scan_keylog_files = lambda: dict(sidecars)
    return controller, pushed, state


def _results_message(pushed):
    from friTap.tui.modals.alert_modal import AlertModal
    for screen, _cb in pushed:
        if isinstance(screen, AlertModal) and screen._title == "Capture Results":
            return screen._message
    raise AssertionError("no Capture Results modal pushed")


class TestKeylogResultRows:

    def test_each_row_shows_its_own_count(self, tmp_path):
        from friTap.tui.capture_controller import KEYLOG_TOTAL_STAT

        hook = _write(tmp_path / "k.log", "CLIENT_RANDOM a b")
        side = _write(tmp_path / "k.mtproto.log", "MTPROTO_AUTH_KEY 1 2",
                      "MTPROTO_AUTH_KEY 3 4", "MTPROTO_AUTH_KEY 5 6")
        controller, _p, _s = _setup(tmp_path, {"tls": hook}, {"mtproto": side})

        stats = controller._gather_result_stats()

        assert stats["Key log"] == "1 key"
        assert stats["Memory-scan keys (mtproto)"] == "3 keys"
        assert stats[KEYLOG_TOTAL_STAT] == "4 keys"

    def test_sidecar_equal_to_hook_keylog_is_listed_once(self, tmp_path):
        """Memory-scan-only: the tls sidecar is the -k path itself."""
        from friTap.tui.capture_controller import KEYLOG_TOTAL_STAT

        keylog = _write(tmp_path / "k.log", "CLIENT_RANDOM a b", "CLIENT_RANDOM c d")
        other_spelling = str(tmp_path / "." / "k.log")
        controller, _p, state = _setup(
            tmp_path, {"tls": keylog}, {"tls": other_spelling},
        )

        rows = controller._keylog_result_rows(state.keylog_path, ["tls"])
        stats = controller._gather_result_stats()

        assert rows == {"Key log": keylog}
        assert stats["Key log"] == "2 keys"
        assert KEYLOG_TOTAL_STAT not in stats

    def test_empty_keylog_shows_zero_keys(self, tmp_path):
        keylog = _write(tmp_path / "k.log")
        controller, _p, _s = _setup(tmp_path, {"tls": keylog}, {})

        assert controller._gather_result_stats()["Key log"] == "0 keys"

    def test_missing_keylog_has_no_count(self, tmp_path):
        missing = str(tmp_path / "never_written.log")
        controller, _p, _s = _setup(tmp_path, {}, {}, base=missing)

        assert "Key log" not in controller._gather_result_stats()


class TestResultsModalRendering:

    def test_modal_lists_rows_once_with_own_counts_and_total(self, tmp_path):
        from friTap.tui.capture_controller import KEYLOG_TOTAL_STAT

        hook = _write(tmp_path / "k.log")
        tls_side = str(tmp_path / "k.log")  # same file as the hook keylog
        mt_side = _write(tmp_path / "k.mtproto.log", "MTPROTO_AUTH_KEY 1 2")
        controller, pushed, _s = _setup(
            tmp_path, {"tls": hook}, {"tls": tls_side, "mtproto": mt_side},
        )

        controller._on_session_ended(controller._gather_result_stats())
        message = _results_message(pushed)

        assert message.count(hook) == 1, message
        assert f"Key log: [bold]{hook}[/] (0 keys)" in message
        assert f"Memory-scan keys (mtproto): [bold]{mt_side}[/] (1 key)" in message
        assert "Memory-scan keys (tls)" not in message
        assert f"{KEYLOG_TOTAL_STAT}: [bold]1 key[/]" in message
