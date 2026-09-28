"""Tests for the display-filter UI: presets, unknown-field hints, help text."""

from __future__ import annotations

import asyncio

import pytest

from friTap.filter import FilterEngine, UnknownFieldError
from friTap.filter.layer_fields import LAYER_FIELD_SPECS
from friTap.filter.presets import (
    FILTER_PRESETS,
    combined_preset_expression,
    preset_label,
)
from friTap.filter.protocols import PROTOCOL_ALIASES, known_protocol_names

# ---------------------------------------------------------------------------
# 1. Presets
# ---------------------------------------------------------------------------

EXPECTED_PRESETS = [
    ("HTTP", "http"),
    ("Errors", "http.response.code >= 400"),
    ("OHTTP", "ohttp.present"),
    ("IPSec", "ipsec"),
    ("SSH", "ssh"),
    ("Telegram", "telegram"),
    ("Signal", "signal"),
]


def test_preset_values():
    assert [(p.label, p.expression) for p in FILTER_PRESETS] == EXPECTED_PRESETS


def test_preset_ids_are_unique_and_keep_legacy_ids():
    ids = [p.toggle_id for p in FILTER_PRESETS]
    assert len(ids) == len(set(ids))
    for legacy in ("toggle-http", "toggle-errors", "toggle-ohttp", "toggle-ipsec", "toggle-ssh"):
        assert legacy in ids


@pytest.mark.parametrize("preset", FILTER_PRESETS, ids=lambda p: p.label)
def test_every_preset_expression_is_valid(preset):
    assert not isinstance(FilterEngine.try_create(preset.expression), str)


def test_combined_preset_expression_ands_in_preset_order():
    combined = combined_preset_expression({"toggle-ssh", "toggle-http"})
    assert combined == "(http) and (ssh)"
    assert combined_preset_expression(set()) == ""
    assert combined_preset_expression({"toggle-bogus"}) == ""


def test_preset_label_falls_back_to_id():
    assert preset_label("toggle-telegram") == "Telegram"
    assert preset_label("toggle-bogus") == "toggle-bogus"


# ---------------------------------------------------------------------------
# 2. try_create_detailed
# ---------------------------------------------------------------------------

def test_try_create_detailed_returns_exception_object():
    err = FilterEngine.try_create_detailed("TELE")
    assert isinstance(err, UnknownFieldError)
    assert "telegram" in err.did_you_mean
    assert isinstance(FilterEngine.try_create_detailed("telegram"), FilterEngine)


# ---------------------------------------------------------------------------
# 3. Pure hint formatting
# ---------------------------------------------------------------------------

from friTap.tui.modals.filter_modal import (  # noqa: E402
    CONTENT_SEARCH_NOTE,
    build_unknown_field_hint,
    suggestion_note,
)


def _unknown(text: str) -> UnknownFieldError:
    err = FilterEngine.try_create_detailed(text)
    assert isinstance(err, UnknownFieldError)
    return err


def _counter(counts: dict[str, int]):
    """A MatchCounter looking engines up by expression."""
    return lambda engine: counts.get(engine.expression)


def test_unknown_field_error_actions_are_ready_to_render():
    err = _unknown("http and TELE")
    assert [(a.kind, a.label) for a in err.actions] == [
        ("protocol_search", 'protocol contains "TELE"'),
        ("method_search", 'method contains "TELE"'),
        ("frame_search", 'frame contains "TELE"'),
        ("field_replacement", "telegram"),
    ]
    assert err.actions[0].expression == 'http and protocol contains "TELE"'
    assert err.suggestions == [a.expression for a in err.actions[:3]]
    op = _unknown("mtprot.dc_id == 2")
    assert op.actions[0].label == "mtproto.dc_id"
    assert op.suggestions == [a.expression for a in op.actions]


def test_hint_for_tele_with_counts():
    counts = {'protocol contains "TELE"': 123, 'method contains "TELE"': 0, "telegram": 45}
    hint = build_unknown_field_hint(_unknown("TELE"), _counter(counts))
    assert hint.message.startswith("Unknown field 'TELE'. Did you mean: telegram, telegram_e2e")
    rows = [(a.key, a.expression, a.note) for a in hint.actions]
    assert rows == [
        ("f2", 'protocol contains "TELE"', "(123 rows)"),
        ("f3", 'method contains "TELE"', "(0 rows)"),
        ("f4", 'frame contains "TELE"', CONTENT_SEARCH_NOTE),
        ("f5", "telegram", "(45 rows)"),
    ]
    width = hint.expression_width
    assert hint.actions[3].body(width) == f"{'telegram':<{width}}  (45 rows)"


def test_hint_never_counts_frame_suggestions():
    calls: list[str] = []

    def counter(engine):
        calls.append(engine.expression)
        return 1

    build_unknown_field_hint(_unknown("TELE"), counter)
    assert calls and not any(expr.startswith("frame") for expr in calls)


def test_hint_counter_errors_are_swallowed():
    def boom(_engine):
        raise RuntimeError("no flows")

    hint = build_unknown_field_hint(_unknown("TELE"), boom)
    assert hint.actions[0].note == ""  # no count, no crash
    assert hint.actions[0].body(hint.expression_width).endswith('"TELE"')


def test_hint_without_counter_has_no_counts():
    assert suggestion_note('protocol contains "x"', None) == ""
    assert suggestion_note('frame contains "x"', None) == CONTENT_SEARCH_NOTE
    assert suggestion_note("not a valid ===", lambda e: 3) == ""


def test_did_you_mean_replaces_only_the_token():
    hint = build_unknown_field_hint(_unknown("http and TELE"))
    by_key = {a.key: a.expression for a in hint.actions}
    assert by_key["f5"] == "http and telegram"
    assert by_key["f2"] == 'http and protocol contains "TELE"'


def test_no_did_you_mean_means_no_f5():
    hint = build_unknown_field_hint(_unknown("getFile"))
    assert [a.key for a in hint.actions] == ["f2", "f3", "f4"]
    assert hint.message == "Unknown field 'getFile'."


def test_unknown_field_error_flags_operator_usage():
    assert _unknown("mtprot.dc_id == 2").followed_by_operator is True
    assert _unknown("TELE").followed_by_operator is False


def test_operator_case_lists_did_you_mean_on_f2_to_f4_without_f5():
    counts = {"mtproto.dc_id == 2": 303}
    hint = build_unknown_field_hint(_unknown("mtprot.dc_id == 2"), _counter(counts))
    assert hint.message == "Unknown field 'mtprot.dc_id'. Did you mean:"
    assert [a.key for a in hint.actions] == ["f2", "f3", "f4"]
    assert hint.actions[0].expression == "mtproto.dc_id == 2"
    assert hint.actions[0].note == "(303 rows)"
    assert not any("contains" in a.expression for a in hint.actions)
    expressions = [a.expression for a in hint.actions]
    assert len(expressions) == len(set(expressions))


def test_operator_case_keeps_the_rest_of_the_expression():
    text = "telegram and htp.host contains x"
    hint = build_unknown_field_hint(_unknown(text))
    assert hint.actions[0].expression == "telegram and http.host contains x"


def test_operator_case_without_did_you_mean_has_no_actions():
    hint = build_unknown_field_hint(_unknown("foo == 3"))
    assert hint.message == "Unknown field 'foo'."
    assert hint.actions == []


def test_is_incomplete_holds_the_lenient_typing_rule():
    for text in ("TELE", "http.resp", "ip.src ==", "http and"):
        err = FilterEngine.try_create_detailed(text)
        assert FilterEngine.is_incomplete(text, err), text
    err = FilterEngine.try_create_detailed("zzzz")
    assert not FilterEngine.is_incomplete("zzzz", err)


# ---------------------------------------------------------------------------
# 4. Help text
# ---------------------------------------------------------------------------

from friTap.filter.fields import FIELD_REGISTRY, get_field  # noqa: E402
from friTap.tui.modals.filter_help_modal import (  # noqa: E402
    _Para,
    _build_filter_help_blocks,
    _build_filter_help_text,
    _static_field_groups,
)
from tests.unit._display_filter_helpers import http_flow  # noqa: E402


def test_help_text_is_plain_rendered_text():
    text = _build_filter_help_text()
    assert text.startswith("Display Filter Reference")
    assert "[/]" not in text
    assert "=== Fields: Generic ===" in text


def test_help_lists_every_protocol_alias_and_layer_field():
    text = _build_filter_help_text()
    for name in known_protocol_names():
        assert name in text, name
    for alias, members in PROTOCOL_ALIASES.items():
        assert f"{alias:<12} -> {', '.join(sorted(members))}" in text
    for spec in LAYER_FIELD_SPECS:
        assert spec.field in text, spec.field
    for field in ("mtproto.dc_id", "telegram.sender", "telegram.e2e"):
        assert field in text, field


def test_help_lists_every_static_field_from_the_registry():
    text = _build_filter_help_text()
    for name, fdef in FIELD_REGISTRY.items():
        assert name in text, name
        assert fdef.description, name
    layer_fields = {spec.field for spec in LAYER_FIELD_SPECS}
    grouped = [row[0] for _, rows in _static_field_groups() for row in rows]
    assert sorted(grouped) == sorted(set(FIELD_REGISTRY) - layer_fields)


def test_help_ungrouped_static_fields_land_in_other():
    groups = dict(_static_field_groups())
    other = [row[0] for row in groups["Other"]]
    for name in ("ohttp.present", "ssh", "ipsec", "telegram.e2e"):
        assert name in other, name


def test_help_documents_generic_fields_presets_and_fixed_example():
    text = _build_filter_help_text()
    for field in ("protocol", "method", "transport", "frame", "info", "process"):
        assert f"  {field:<24} " in text
    assert "  protocol                 str* " in text
    for preset in FILTER_PRESETS:
        assert preset.expression in text
    assert '"HTTP/1.1"' not in text
    assert "HTTP/1.x" in text
    for example in ('method == "upload.getFile"', 'frame contains "password"',
                    "telegram and not method contains msgs_ack", 'r"..."'):
        assert example in text


def test_help_telegram_e2e_is_a_valid_field():
    assert not isinstance(FilterEngine.try_create("telegram.e2e"), str)


def test_help_lists_http1_as_a_static_field():
    fdef = get_field("http1")
    assert fdef is FIELD_REGISTRY["http1"]
    assert fdef.description == "HTTP/1.x flow"
    engine = FilterEngine("http1")
    assert engine.matches(http_flow("HTTP/1.1"))
    assert not engine.matches(http_flow("HTTP/2"))
    assert "  http1                    bool     HTTP/1.x flow" in _build_filter_help_text()


def test_help_markup_is_valid():
    from rich.text import Text

    for block in _build_filter_help_blocks():
        if isinstance(block, _Para):
            Text.from_markup(block.markup)


def test_help_examples_are_valid_filters():
    for example in ('frame.protocol == "HTTP/1.x"', "frame.protocol == http1",
                    'protocol contains "tele"', "mtproto.dc_id == 2",
                    'signal.msg contains "hi"'):
        assert not isinstance(FilterEngine.try_create(example), str), example


# ---------------------------------------------------------------------------
# 5. Textual pilot tests of the modal
# ---------------------------------------------------------------------------

pytest.importorskip("textual")

from textual.widgets import Input, Static  # noqa: E402

from friTap.tui.app import FriTapApp  # noqa: E402
from friTap.tui.modals.filter_modal import FilterModal  # noqa: E402


def _run(body, size=(100, 40)):
    async def _main() -> None:
        app = FriTapApp()
        async with app.run_test(size=size) as pilot:
            await body(app, pilot)

    asyncio.run(_main())


def _static_text(modal, widget_id: str) -> str:
    return str(modal.query_one(widget_id, Static).render())


async def _type_and_settle(pilot, text: str) -> None:
    for ch in text:
        await pilot.press(ch)
    await pilot.pause(0.4)  # > 250ms debounce


def test_modal_typing_tele_shows_hints_and_f2_applies():
    seen: dict = {}

    def counter(engine):
        return 7 if engine.expression.startswith("protocol") else 0

    async def body(app, pilot):
        modal = FilterModal(match_counter=counter)
        await app.push_screen(modal)
        await pilot.pause()
        await _type_and_settle(pilot, "TELE")
        seen["hints_visible"] = modal.query_one("#filter-hints").display
        seen["message"] = _static_text(modal, "#filter-hint-message")
        seen["f2"] = _static_text(modal, "#filter-hint-f2")
        seen["f3"] = _static_text(modal, "#filter-hint-f3")
        seen["f4"] = _static_text(modal, "#filter-hint-f4")
        await pilot.press("f2")
        await pilot.pause()
        inp = modal.query_one("#filter-input", Input)
        seen["after_f2"] = inp.value
        seen["valid"] = inp.has_class("valid")
        seen["hints_after"] = modal.query_one("#filter-hints").display

    _run(body)
    assert seen["hints_visible"] is True
    assert "Did you mean: telegram" in seen["message"]
    assert 'protocol contains "TELE"' in seen["f2"] and "(7 rows)" in seen["f2"]
    assert 'method contains "TELE"' in seen["f3"] and "(0 rows)" in seen["f3"]
    assert 'frame contains "TELE"' in seen["f4"] and CONTENT_SEARCH_NOTE in seen["f4"]
    assert seen["after_f2"] == 'protocol contains "TELE"'
    assert seen["valid"] is True
    assert seen["hints_after"] is False


def test_modal_f5_applies_did_you_mean_and_enter_dismisses():
    result: dict = {}

    async def body(app, pilot):
        modal = FilterModal()
        await app.push_screen(modal, callback=lambda v: result.setdefault("v", v))
        await pilot.pause()
        await _type_and_settle(pilot, "TELE")
        await pilot.press("f5")
        await pilot.pause()
        result["value"] = modal.query_one("#filter-input", Input).value
        await pilot.press("enter")
        await pilot.pause()

    _run(body)
    assert result["value"] == "telegram"
    assert result["v"].text == "telegram"
    assert result["v"].text_engine is not None


def test_modal_strict_enter_on_unknown_field_keeps_modal_and_shows_hint():
    seen: dict = {}

    async def body(app, pilot):
        modal = FilterModal()
        await app.push_screen(modal, callback=lambda v: seen.setdefault("dismissed", v))
        await pilot.pause()
        for ch in "zzz":
            await pilot.press(ch)
        await pilot.press("enter")
        await pilot.pause()
        seen["hints_visible"] = modal.query_one("#filter-hints").display
        seen["f2"] = _static_text(modal, "#filter-hint-f2")

    _run(body)
    assert "dismissed" not in seen
    assert seen["hints_visible"] is True
    assert 'protocol contains "zzz"' in seen["f2"]


def test_modal_operator_unknown_field_shows_did_you_mean_and_f2_applies():
    seen: dict = {}

    async def body(app, pilot):
        modal = FilterModal()
        await app.push_screen(modal)
        await pilot.pause()
        await _type_and_settle(pilot, "mtprot.dc_id == 2")
        seen["message"] = _static_text(modal, "#filter-hint-message")
        seen["f2"] = _static_text(modal, "#filter-hint-f2")
        seen["f5_visible"] = modal.query_one("#filter-hint-f5").display
        await pilot.press("f2")
        await pilot.pause()
        inp = modal.query_one("#filter-input", Input)
        seen["after_f2"] = inp.value
        seen["valid"] = inp.has_class("valid")

    _run(body)
    assert seen["message"] == "Unknown field 'mtprot.dc_id'. Did you mean:"
    assert "mtproto.dc_id == 2" in seen["f2"] and "contains" not in seen["f2"]
    assert seen["f5_visible"] is False
    assert seen["after_f2"] == "mtproto.dc_id == 2"
    assert seen["valid"] is True


def test_modal_telegram_preset_builds_toggle_engine():
    result: dict = {}

    async def body(app, pilot):
        modal = FilterModal()
        await app.push_screen(modal, callback=lambda v: result.setdefault("v", v))
        await pilot.pause()
        await pilot.click("#toggle-telegram")
        await pilot.click("#toggle-signal")
        await pilot.pause()
        await pilot.click("#btn-apply")
        await pilot.pause()

    _run(body)
    assert result["v"].active_toggles == {"toggle-telegram", "toggle-signal"}
    assert result["v"].toggle_engine.expression == "(telegram) and (signal)"


def test_modal_enter_after_toggle_click_applies_instead_of_untoggling():
    result: dict = {}

    async def body(app, pilot):
        modal = FilterModal()
        await app.push_screen(modal, callback=lambda v: result.setdefault("v", v))
        await pilot.pause()
        await pilot.click("#toggle-telegram")
        await pilot.pause()
        result["focused"] = app.focused.id
        await pilot.press("enter")
        await pilot.pause()

    _run(body)
    assert result["focused"] == "toggle-telegram"
    assert result["v"].active_toggles == {"toggle-telegram"}
    assert result["v"].toggle_engine.expression == "(telegram)"


def test_modal_space_toggles_focused_preset_but_types_in_input():
    seen: dict = {}

    async def body(app, pilot):
        modal = FilterModal()
        await app.push_screen(modal, callback=lambda v: seen.setdefault("v", v))
        await pilot.pause()
        await pilot.press("a", "space", "b")
        seen["typed"] = modal.query_one("#filter-input", Input).value
        modal.query_one("#toggle-signal").focus()
        await pilot.press("space")
        await pilot.pause()
        seen["active"] = set(modal._active_toggles)
        await pilot.press("space")
        await pilot.pause()
        seen["after_second"] = set(modal._active_toggles)

    _run(body)
    assert seen["typed"] == "a b"
    assert seen["active"] == {"toggle-signal"}
    assert seen["after_second"] == set()
    assert "v" not in seen


def test_modal_enter_on_cancel_button_presses_it():
    result: dict = {}

    async def body(app, pilot):
        modal = FilterModal()
        await app.push_screen(modal, callback=lambda v: result.setdefault("v", v))
        await pilot.pause()
        await pilot.press("h", "t", "t", "p")
        modal.query_one("#btn-cancel").focus()
        await pilot.press("enter")
        await pilot.pause()

    _run(body)
    assert result["v"] is None


def test_modal_unknown_field_message_is_shown_once():
    seen: dict = {}

    async def body(app, pilot):
        modal = FilterModal()
        await app.push_screen(modal)
        await pilot.pause()
        await _type_and_settle(pilot, "TELE")
        seen["lenient_status"] = _static_text(modal, "#filter-status")
        seen["message"] = _static_text(modal, "#filter-hint-message")
        await pilot.press("enter")
        await pilot.pause()
        seen["strict_status"] = _static_text(modal, "#filter-status")
        seen["invalid"] = modal.query_one("#filter-input", Input).has_class("invalid")

    _run(body)
    assert "Unknown field 'TELE'" in seen["message"]
    assert "Unknown field" not in seen["lenient_status"]
    assert "Unknown field" not in seen["strict_status"]
    assert seen["invalid"] is True


def test_modal_count_cache_refreshes_when_row_count_changes():
    counts = iter(range(1, 100))
    rows = {"n": 10}

    def counter(_engine):
        return next(counts)

    seen: dict = {}

    async def body(app, pilot):
        modal = FilterModal(match_counter=counter, row_count=lambda: rows["n"])
        await app.push_screen(modal)
        await pilot.pause()
        await _type_and_settle(pilot, "TELE")
        seen["first"] = _static_text(modal, "#filter-hint-f2")
        modal._validate_lenient()
        await pilot.pause()
        seen["same_rows"] = _static_text(modal, "#filter-hint-f2")
        rows["n"] = 11
        modal._validate_lenient()
        await pilot.pause()
        seen["new_rows"] = _static_text(modal, "#filter-hint-f2")

    _run(body)
    assert seen["first"] == seen["same_rows"]
    assert seen["first"] != seen["new_rows"]


def test_modal_key_hint_does_not_promise_question_mark_help():
    seen: dict = {}

    async def body(app, pilot):
        modal = FilterModal()
        await app.push_screen(modal)
        await pilot.pause()
        seen["hint"] = str(modal.query_one(".key-hints", Static).render())

    _run(body)
    assert "F1: Help" in seen["hint"] and "?: Help" not in seen["hint"]
    assert "Enter: Apply" in seen["hint"]
