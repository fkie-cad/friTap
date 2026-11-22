"""Pre-argparse routing of ``fritap`` argv to subcommands and special modes."""


def _looks_like_tap_input(token):
    """Return True when ``token`` looks like a ``.tap`` capture file argument.

    Used to disambiguate the bare ``analyze`` mode from a capture target that
    happens to be named ``analyze`` (see :func:`_dispatch_special_mode`).
    A token is treated as a ``.tap`` input only if it is a non-flag argument
    ending in ``.tap``.
    """
    return bool(token) and not token.startswith("-") and token.endswith(".tap")


_SUBCOMMAND_HELP_FLAGS = ("-h", "--help")


def _selects_tap_subcommand(argv, name):
    """True when ``argv`` is ``fritap <name> <file.tap> ...`` or ``fritap <name> -h|--help``.

    The help form is safe to route: a capture of a process named ``<name>``
    followed by only ``-h`` would just print the capture help, so nothing is
    lost, and ``fritap analyze --help`` now shows the analyze options. Any
    other next token (e.g. ``-m``) still falls through to capture.
    """
    if len(argv) < 3 or argv[1] != name:
        return False
    return _looks_like_tap_input(argv[2]) or argv[2] in _SUBCOMMAND_HELP_FLAGS


def _looks_like_pcap_input(token):
    """Return True when ``token`` looks like a pcap/pcapng capture file argument.

    Used by :func:`_dispatch_special_mode` to route ``fritap -r capture.pcap``
    (and the bare trailing-path form) into the guided pcap-to-tap wizard rather
    than the ``.tap`` replay path. A token qualifies only if it is a non-flag
    argument ending in ``.pcap`` or ``.pcapng``.
    """
    return bool(token) and not token.startswith("-") and (
        token.endswith(".pcap") or token.endswith(".pcapng")
    )


def _agent_api_mode(argv):
    """Return ``"q"``, ``"mcp"``, ``"serve"`` or ``None`` for an agent-API invocation.

    ``q`` needs leading q-level options, ``--list``/``-h``/``--help`` or a
    registered (or closely misspelled) tool name next (see
    ``agent_api.adapters.cli.is_query_invocation``); ``mcp``/``serve`` need
    every following token to be an option of their argparse parser.
    """
    if len(argv) < 2 or argv[1] not in _AGENT_API_COMMANDS:
        return None
    if argv[1] == "q":
        from .commands.query import is_query_invocation as matches
    elif argv[1] == "mcp":
        from .commands.mcp import is_mcp_invocation as matches
    else:
        from .commands.serve import is_serve_invocation as matches
    return argv[1] if matches(argv) else None


_AGENT_API_COMMANDS = ("q", "mcp", "serve")


def _dispatch_special_mode(argv):
    """Resolve the pre-argparse "special mode" from a raw ``argv`` list.

    Leading positional/flag forms must be handled before the capture argparse
    parser sees them. ``argv`` is the full ``sys.argv``; dispatch inspects
    ``argv[1]`` onward.

    Returns a ``(mode, payload)`` tuple where ``mode`` is one of:

    * ``"list-analyzers"``: ``fritap --list-analyzers``: print the available
      analyzers (built-in + discovered externals) and exit. ``payload`` is
      ``None``; needs no target.
    * ``"install-backend"``: ``fritap install-backend <name>``: install an
      external integration (currently only the Wireshark extcap). ``payload``
      is the backend name (``argv[2]``).
    * ``"from-pcap"``: ``fritap --from-pcap capture.pcapng [...]``:
      offline decryption of an encrypted pcap into a ``.tap`` file. ``payload``
      is ``argv[1:]`` (forwarded verbatim to the offline CLI).
    * ``"analyze"``: ``fritap --analyze ...`` or ``fritap analyze
      capture.tap``: passive offline analysis of an existing ``.tap``. ``payload``
      is the argument list after the mode token (``argv[2:]``). ``fritap
      analyze -h|--help`` (and the same for ``report``) also routes here.
    * ``"replay"``: ``fritap -r capture.tap``, ``fritap --replay
      capture.tap`` or ``fritap capture.tap``: open the capture in the TUI.
      ``payload`` is the ``.tap`` path, or ``None`` when ``-r`` was given
      without a file (caller prints usage).
    * ``"pcap-wizard"``: ``fritap -r capture.pcap``, ``fritap --replay
      capture.pcapng`` or ``fritap capture.pcap``: launch the guided pcap-to-tap
      wizard (confirm input, choose output ``.tap``, supply TLS + per-protocol
      keylogs, convert, then open the result in the replay TUI). ``payload`` is
      the pcap/pcapng path.
    * ``"q"`` / ``"mcp"`` / ``"serve"``: agent API: ``fritap q <tool>`` runs one
      registry tool and prints JSON; ``fritap mcp`` / ``fritap serve`` start the
      MCP / REST server. ``payload`` is ``argv[2:]``. See :func:`_agent_api_mode`.
    * ``"skills"``: ``fritap skills [list|show|install ...]``: the
      bundled agent skills (see :mod:`friTap.commands.skills`). ``payload`` is
      ``argv[2:]``.
    * ``None``: no special mode; fall through to normal capture.

    Disambiguation: bare ``analyze`` is the analyze subcommand only when the
    next token looks like a ``.tap`` input (``_looks_like_tap_input``), unlike
    the explicit ``--analyze`` flag. A process literally named ``analyze``
    (``fritap analyze``, ``fritap analyze -m``) falls through to capture.
    """
    # --list-analyzers needs no target and may appear anywhere in argv.
    if len(argv) >= 2 and "--list-analyzers" in argv[1:]:
        return ("list-analyzers", None)

    if len(argv) >= 3 and argv[1] == "install-backend":
        return ("install-backend", argv[2])

    # --from-pcap may appear anywhere in the argument list.
    if len(argv) >= 2 and "--from-pcap" in argv:
        return ("from-pcap", argv[1:])

    # Analyze: explicit --analyze always wins; bare 'analyze' only when it is
    # followed by a .tap input, so a target named 'analyze' is not hijacked.
    if len(argv) >= 2 and argv[1] == "--analyze":
        return ("analyze", argv[2:])
    if _selects_tap_subcommand(argv, "analyze"):
        return ("analyze", argv[2:])
    # Report (AI-agent digest): same rule, only when followed by a .tap input.
    if _selects_tap_subcommand(argv, "report"):
        return ("report", argv[2:])
    # devices / apps listing: only when every following token is a listing
    # option, so `fritap apps -k keys.log` still captures a process named 'apps'.
    from .commands.devices import is_listing_invocation
    if is_listing_invocation(argv):
        return (argv[1], argv[2:])
    # skills: list/show/install the bundled agent skills (same guard idea).
    from .commands.skills import is_skills_invocation
    if is_skills_invocation(argv):
        return ("skills", argv[2:])
    # Agent API: `fritap q <tool>|--list`, `fritap mcp`, `fritap serve`; same
    # guard idea, so a target named q/mcp/serve with capture flags still captures.
    agent_mode = _agent_api_mode(argv)
    if agent_mode is not None:
        return (agent_mode, argv[2:])

    # Replay / pcap-wizard: -r/--replay <file>, or a single trailing path.
    # A .pcap/.pcapng input opens the guided pcap-to-tap wizard (convert +
    # replay); a .tap input opens the replay TUI directly.
    if len(argv) >= 2 and argv[1] in ("-r", "--replay"):
        target = argv[2] if len(argv) >= 3 else None
        if _looks_like_pcap_input(target):
            return ("pcap-wizard", target)
        return ("replay", target)
    if len(argv) == 2 and _looks_like_pcap_input(argv[1]):
        return ("pcap-wizard", argv[1])
    if len(argv) == 2 and argv[1].endswith(".tap"):
        return ("replay", argv[1])

    return None


# Subcommand runners for main(). Each takes ``(kind, payload)`` from
# _dispatch_special_mode and imports its command module lazily, so a plain
# capture never loads them.
def _run_install_backend(_kind, payload):
    if payload == "wireshark":
        from .commands.install_backend import install_wireshark_extcap
        install_wireshark_extcap()
        return
    print(f"Unknown backend: {payload}. Available: wireshark")


def _run_from_pcap(_kind, payload):
    from .offline.cli import run_offline_pcap_to_tap
    return run_offline_pcap_to_tap(payload)


def _run_list_analyzers(_kind, _payload):
    from .commands.analyze import (
        _format_analyzer_listing,
        list_analyzers_detailed,
    )
    print(_format_analyzer_listing(list_analyzers_detailed()))


def _run_analyze(_kind, payload):
    from .commands.analyze import run_analyze_cli
    return run_analyze_cli(payload)


def _run_report(_kind, payload):
    from .commands.report import run_report_cli
    return run_report_cli(payload)


def _run_listing(kind, payload):
    from .commands.devices import run_listing_cli
    return run_listing_cli(kind, payload)


def _run_skills(_kind, payload):
    from .commands.skills import run_skills_cli
    return run_skills_cli(payload)


def _run_query(_kind, payload):
    from .commands.query import run_query_cli
    return run_query_cli(payload)


def _run_mcp(_kind, payload):
    from .commands.mcp import run_mcp_cli
    return run_mcp_cli(payload)


def _run_serve(_kind, payload):
    from .commands.serve import run_serve_cli
    return run_serve_cli(payload)


_SUBCOMMAND_RUNNERS = {
    "install-backend": _run_install_backend,
    "from-pcap": _run_from_pcap,
    "list-analyzers": _run_list_analyzers,
    "analyze": _run_analyze,
    "report": _run_report,
    "devices": _run_listing,
    "apps": _run_listing,
    "skills": _run_skills,
    "q": _run_query,
    "mcp": _run_mcp,
    "serve": _run_serve,
}
