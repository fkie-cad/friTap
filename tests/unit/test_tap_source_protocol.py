"""Conformance of ReplayController and FakeReplay to the TapSource protocol."""

import inspect

import pytest

from friTap.flow.replay import ReplayController, TapSource
from tests.unit._tui_flow_helpers import FakeReplay

METHODS = (
    "get_summaries",
    "get_flow",
    "store_reparse",
    "read_all_findings",
    "read_request_contexts",
)


def _implementations():
    return [ReplayController("unused.tap"), FakeReplay([])]


@pytest.mark.parametrize("impl", _implementations(), ids=["controller", "fake"])
def test_isinstance_tap_source(impl):
    assert isinstance(impl, TapSource)
    assert hasattr(impl, "header")


@pytest.mark.parametrize("impl", _implementations(), ids=["controller", "fake"])
@pytest.mark.parametrize("name", METHODS)
def test_method_parameter_names_match(impl, name):
    expected = list(inspect.signature(getattr(TapSource, name)).parameters)
    actual = list(inspect.signature(getattr(impl, name)).parameters)
    assert actual == [p for p in expected if p != "self"]


PROPERTIES = ("header", "flow_count")


def _protocol_members() -> set[str]:
    return {
        name for name in vars(TapSource)
        if not name.startswith("_")
    }


def test_protocol_lists_every_member_the_viewer_uses():
    """flow_count (banner, _has_flows) and get_flows (w-export) are members."""
    assert _protocol_members() == set(METHODS) | set(PROPERTIES) | {"get_flows"}


def test_close_is_optional_not_a_protocol_member():
    assert "close" not in _protocol_members()
    assert "close" in (TapSource.__doc__ or "")


@pytest.mark.parametrize("impl", _implementations(), ids=["controller", "fake"])
def test_flow_count_and_get_flows_conform(impl):
    assert impl.flow_count == 0
    assert list(impl.get_flows()) == []
    assert list(inspect.signature(impl.get_flows).parameters) == []


def test_fake_replay_flow_count_and_get_flows():
    from tests.unit._tui_flow_helpers import make_flow

    flows = [make_flow("f1"), make_flow("f2")]
    fake = FakeReplay(flows)
    assert fake.flow_count == 2
    assert [f.flow_id for f in fake.get_flows()] == ["f1", "f2"]
