"""Tests for the drift-check helpers in ``_skill_lint`` (synthetic Markdown)."""

from __future__ import annotations

import pytest

from friTap.agent_api.registry import registry

from . import _skill_lint as lint
from .conftest import write_skill

FENCE = "```"


def block(*lines, lang="bash"):
    return "\n".join([FENCE + lang, *lines, FENCE]) + "\n"


def test_fenced_lines_only_inside_fences_and_joins_continuations():
    text = "fritap --outside\n" + block("fritap -k a \\", "  --pcap b.pcap", "echo hi")
    assert list(lint.fenced_lines(text)) == ["fritap -k a    --pcap b.pcap", "echo hi"]


@pytest.mark.parametrize("line, expected", [
    ("fritap -k keys.log app", ["-k", "keys.log", "app"]),
    ("$ fritap --pcap x.pcap app", ["--pcap", "x.pcap", "app"]),
    ("sudo -E fritap -m app", ["-m", "app"]),
    ("$ sudo fritap -m app  # comment --nope", ["-m", "app"]),
    ("fritap --bogus app  # noqa-flag", None),
    ("echo fritap --x", None),
    ("fritap 'unbalanced --pcap", ["'unbalanced", "--pcap"]),
])
def test_fritap_command_args(line, expected):
    assert lint.fritap_command_args(line) == expected


def test_long_options_strip_values_and_stop_at_double_dash():
    tokens = ["--pcap=x", "-k", "--json", "--", "wine", "--not-ours"]
    assert lint.long_options(tokens) == ["--pcap", "--json"]


def test_referenced_tools_from_prose_and_code():
    text = "Run `fritap q get_digest --tap t` then\n" + block(
        "fritap q --compact list_endpoints --tap t", "fritap q --list")
    assert lint.referenced_tools(text) == {"get_digest", "list_endpoints"}


def test_markdown_files_include_references(tmp_path):
    skill_dir = write_skill(tmp_path, "s")
    names = sorted(doc.name for doc in lint.markdown_files(skill_dir))
    assert names == ["SKILL.md", "guide.md"]


def test_known_capture_options_are_accepted():
    text = block("fritap -m -k keys.log --pcap out.pcap com.example.app")
    assert lint.unknown_options(text) == []


def test_unknown_capture_option_is_reported():
    problems = lint.unknown_options(block("fritap --definitely-not-a-flag app"))
    assert [option for _, option in problems] == ["--definitely-not-a-flag"]


def test_q_tool_params_come_from_schema():
    tool = registry.get("get_digest")
    param = next(iter(tool.params_schema.get("properties", {})))
    flag = "--" + param.replace("_", "-")
    assert lint.unknown_options(block(f"fritap q get_digest {flag} x --compact")) == []
    bad = lint.unknown_options(block("fritap q get_digest --no-such-param 1"))
    assert [option for _, option in bad] == ["--no-such-param"]


@pytest.mark.parametrize("command", [
    "fritap q --list --json",
    "fritap mcp --allow-capture --root .",
    "fritap serve --allow-capture",
    "fritap devices --json",
    "fritap apps --running --json",
    "fritap skills install --target x --force",
    "fritap skills list --json",
    "fritap report run.tap --focus privacy --budget 800",
    "fritap analyze run.tap",
    "fritap --analyze run.tap",
    "fritap --from-pcap c.pcapng --keylog k.log --tap o.tap",
])
def test_subcommand_options_are_accepted(command):
    assert lint.unknown_options(block(command)) == []


def test_subcommand_option_not_leaking_into_other_command():
    problems = lint.unknown_options(block("fritap devices --force"))
    assert [option for _, option in problems] == ["--force"]
