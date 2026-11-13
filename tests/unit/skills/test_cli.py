"""Tests for ``fritap skills`` (list/show/install) and its dispatch."""

from __future__ import annotations

import io
import json

import pytest

import friTap.friTap as fritap_cli
from friTap.commands import skills as skills_cli
from friTap.exit_codes import EXIT_OK, EXIT_RUNTIME_ERROR, EXIT_USAGE_ERROR


def run(tokens):
    out, err = io.StringIO(), io.StringIO()
    code = skills_cli.run_skills_cli(tokens, out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def test_list_prints_name_and_first_description_line(two_skills):
    code, out, _ = run(["list"])
    assert code == EXIT_OK
    lines = out.splitlines()
    assert lines[0].split() == ["alpha-skill", "Alpha", "first", "line."]
    assert "Second line" not in out
    assert lines[1].startswith("zeta-skill")


def test_bare_skills_lists(two_skills):
    assert run([])[1] == run(["list"])[1]


def test_list_json_is_array(two_skills):
    code, out, _ = run(["list", "--json"])
    rows = json.loads(out)
    assert code == EXIT_OK
    assert [r["name"] for r in rows] == ["alpha-skill", "zeta-skill"]
    assert rows[0]["description"].startswith("Alpha first line.")


def test_list_json_empty(fake_root):
    assert json.loads(run(["list", "--json"])[1]) == []


def test_show_prints_skill_md(two_skills):
    code, out, _ = run(["show", "zeta-skill"])
    assert code == EXIT_OK
    assert out.startswith("---\nname: zeta-skill") and "# Body" in out


def test_show_unknown_skill(two_skills):
    code, _, err = run(["show", "nope"])
    assert code == EXIT_USAGE_ERROR and "nope" in err


def test_install_default_target_is_claude_skills(two_skills, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    code, out, _ = run(["install"])
    assert code == EXIT_OK
    assert (tmp_path / ".claude" / "skills" / "alpha-skill" / "references" / "guide.md").is_file()
    assert out.count("installed ") == 2


def test_install_names_and_target(two_skills, tmp_path):
    code, _, _ = run(["install", "alpha-skill", "--target", str(tmp_path / "t")])
    assert code == EXIT_OK
    assert [p.name for p in (tmp_path / "t").iterdir()] == ["alpha-skill"]


def test_install_no_overwrite_then_force(two_skills, tmp_path):
    target = str(tmp_path / "t")
    assert run(["install", "--target", target])[0] == EXIT_OK
    code, _, err = run(["install", "--target", target])
    assert code == EXIT_RUNTIME_ERROR and "--force" in err
    assert run(["install", "--target", target, "--force"])[0] == EXIT_OK


def test_install_unknown_name(two_skills, tmp_path):
    code, _, err = run(["install", "nope", "--target", str(tmp_path)])
    assert code == EXIT_USAGE_ERROR and "nope" in err


@pytest.mark.parametrize("text, expected", [("a\nb", "a"), ("\n  x  \n", "x"), ("", "")])
def test_first_line(text, expected):
    assert skills_cli.first_line(text) == expected


@pytest.mark.parametrize("argv, expected", [
    (["fritap", "skills"], True),
    (["fritap", "skills", "list"], True),
    (["fritap", "skills", "show", "x"], True),
    (["fritap", "skills", "install", "--force"], True),
    (["fritap", "skills", "--help"], True),
    (["fritap", "skills", "-k", "keys.log"], False),
    (["fritap", "other", "list"], False),
    (["fritap"], False),
])
def test_is_skills_invocation(argv, expected):
    assert skills_cli.is_skills_invocation(argv) is expected


def test_dispatcher_routes_skills():
    assert fritap_cli._dispatch_special_mode(["fritap", "skills", "list"]) == ("skills", ["list"])
    assert fritap_cli._dispatch_special_mode(["fritap", "skills", "-k", "k.log"]) is None


def test_main_runs_skills_subcommand(two_skills, monkeypatch, capsys):
    monkeypatch.setattr(fritap_cli.sys, "argv", ["fritap", "skills", "list", "--json"])
    assert fritap_cli.main() == EXIT_OK
    assert [r["name"] for r in json.loads(capsys.readouterr().out)] == ["alpha-skill", "zeta-skill"]
