"""
``fritap q`` — call any agent tool from the shell and get JSON back.

    fritap q --list
    fritap q get_digest --tap run.tap --budget 800
    fritap q list_endpoints --json '{"tap": "run.tap", "limit": 20}' --compact

Thin entry point; the generated CLI lives in :mod:`friTap.agent_api.adapters.cli`.
Dispatch guard (see ``friTap.friTap._dispatch_special_mode`` and
:func:`friTap.agent_api.adapters.cli.is_query_invocation`): ``q`` is this
subcommand after leading q-level options, before ``--list``/``-h``/``--help``,
or before a registered tool name (or a close misspelling of one); ``fritap q
-k keys.log``, ``fritap q firefox`` and ``fritap q com.example.my_app`` still
capture a process named ``q``.
"""

from __future__ import annotations


def is_query_invocation(argv: list[str]) -> bool:
    """True when ``argv`` (``sys.argv``) selects ``fritap q`` (see module docstring)."""
    from friTap.agent_api.adapters.cli import is_query_invocation as _is_query

    def tool_names() -> list[str]:
        from friTap.agent_api.registry import registry
        return registry.names()

    return _is_query(argv, tool_names)


def run_query_cli(tokens: list[str]) -> int:
    """Run ``fritap q <tokens>``; returns the process exit code."""
    from friTap.agent_api.adapters.cli import run_query_cli as _run

    return _run(tokens)
