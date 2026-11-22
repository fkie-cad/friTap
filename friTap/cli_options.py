"""Post-parse normalisation and validation of the capture CLI options.

Helpers either mutate ``parsed`` in place or report through ``parser.error``
(exit 2), so ``cli()`` can call them in a fixed order.
"""

import logging
import re
import sys

from .backends.base import BackendName
from .fritap_utility import Failure
from .legacy.ssl_logger_core import WINE_BASENAMES

# Capture-output flags that produce nothing in probe mode, paired with the
# spelling the user typed so the warning quotes their own command line back.
_PROBE_IGNORED_CAPTURE_FLAGS = (
    ("keylog", "-k/--keylog"),
    ("pcap", "-p/--pcap"),
    ("full_capture", "-f/--full_capture"),
    ("live", "--live"),
    ("json", "-j/--json"),
)


def _probe_conflict_warnings(parsed):
    """Return the warning lines for capture flags that do nothing under --probe.

    Pure so the wording stays testable.

    Warn, never error: --probe is added to the command line the user is already
    debugging, so rejecting it would defeat the purpose. No hooks are installed
    in probe mode, so every output flag would only create an empty file.
    """
    if not getattr(parsed, "probe", False):
        return []
    ignored = [
        label for attr, label in _PROBE_IGNORED_CAPTURE_FLAGS
        if getattr(parsed, attr, None)
    ]
    if not ignored:
        return []
    return [
        "--probe is a dry run: friTap installs no hooks, so these flags produce "
        "no data and are ignored: " + ", ".join(ignored) + ".",
        "  -> Re-run the same command without --probe once the probe report looks healthy.",
    ]


def _apply_non_interactive_flag(parsed):
    """--non-interactive implies -y/--yes (auto-confirm every prompt)."""
    if getattr(parsed, "non_interactive", False):
        parsed.yes = True


def _validate_duration(parsed, parser):
    """--duration must be a positive number of seconds."""
    duration = getattr(parsed, "duration", None)
    if duration is not None and not duration > 0:
        parser.error("--duration must be a positive number of seconds")


_CONSOLE_LOGGER_NAMES = ("friTap", "friTap.no_prefix")


def _is_console_handler(handler):
    """A StreamHandler writing to stdout/stderr (not the debug-log proxy)."""
    return (isinstance(handler, logging.StreamHandler)
            and getattr(handler, "stream", None) in (sys.stdout, sys.stderr))


def _apply_quiet_console(quiet):
    """--quiet: raise the console handlers of friTap's loggers to WARNING.

    Only console StreamHandlers are touched; --debug-log / -do file handlers
    keep logging everything."""
    if not quiet:
        return
    for name in _CONSOLE_LOGGER_NAMES:
        for handler in logging.getLogger(name).handlers:
            if _is_console_handler(handler):
                handler.setLevel(logging.WARNING)


def _resolve_backend_choice(parsed):
    """Record whether --backend was passed, then fall back to the default.

    None means the user did not pass it; explicitness drives Wine-route precedence.
    """
    parsed.backend_explicit = parsed.backend is not None
    if parsed.backend is None:
        parsed.backend = BackendName.FRIDA


def _split_exec_argv(parsed):
    """Keep the target tokens in ``exec_argv`` and join ``exec`` into one string."""
    # The target positional takes one or more tokens (nargs="+") so a spawn
    # command with arguments parses, e.g. `wine /path/app.exe`.
    # Keep the original token list as parsed.exec_argv so spawn can pass the real
    # argv to device.spawn() (preserving paths that contain spaces, e.g.
    # ".../Program Files/app.exe"), and collapse parsed.exec to the single
    # space-joined string the rest of friTap expects for attach-by-name/display.
    if isinstance(parsed.exec, list):
        parsed.exec_argv = list(parsed.exec)
        parsed.exec = " ".join(parsed.exec)
    else:
        parsed.exec_argv = None


def _resolve_protocols(parsed, parser):
    """Set ``parsed.protocols`` (validated selection) and ``parsed.protocol``.

    ``protocols`` is the canonical selection; ``protocol`` is its first (primary)
    element, for code that handles a single value.
    """
    from friTap.protocols.registry import available_protocol_names as _avail_names
    parsed.protocols = _normalize_protocol_selection(
        parsed.protocol, parser, _avail_names()
    )
    parsed.protocol = parsed.protocols[0]


def _confirm_protocol_all(parsed, parser, logger):
    """--protocol all: make the user confirm, unless -y/--yes was given."""
    # auto is the script-friendly alias (same hooks, no prompt) for unattended runs.
    if "all" in parsed.protocols and not parsed.yes:
        if not sys.stdin.isatty():
            parser.error(
                "--protocol all requires interactive confirmation. Pass -y/--yes "
                "to skip the prompt, or use --protocol auto for the same effect."
            )
        sys.stderr.write(
            "--protocol all will hook TLS, QUIC, OHTTP, SSH, and IPsec libraries\n"
            "simultaneously. This may slow the target process, increase capture\n"
            "volume, and produce a mixed keylog and PCAPNG. Consider --protocol\n"
            "<one> for a focused capture. Continue? [y/N] "
        )
        sys.stderr.flush()
        answer = sys.stdin.readline().strip().lower()
        if answer not in ("y", "yes"):
            logger.info("Aborted by user.")
            raise Failure


def _auto_enable_sshd_child_gating(parsed, logger):
    """Follow sshd's forks: enable child gating for an sshd target."""
    if "ssh" in parsed.protocols:
        # sshd forks a pre-auth child for KEX and re-execs into sshd-session post-auth.
        # Frida hooks only follow forks when child-gating is on. Auto-enable when the
        # target name looks like an sshd binary.
        target = (getattr(parsed, "exec", "") or "")
        target_basename = target.rsplit("/", 1)[-1]
        if re.match(r"^sshd(-session)?$", target_basename) and not parsed.enable_child_gating:
            logger.info("[ssh] sshd target detected — enabling --enable_child_gating automatically")
            parsed.enable_child_gating = True


def _validate_protocol_cli_intent(parsed, parser, logger):
    """Let each selected protocol's handler validate or adjust the CLI intent.

    Keeps protocol-specific rules (e.g. the MTProto/Telegram spawn nudge and
    capture-intent gate) with the handler, out of the generic parser. Every
    selected protocol is checked, not just the primary; meta values
    ('all'/'auto') and unknown names have no single handler and are skipped.
    """
    from friTap.protocols.registry import (
        available_protocol_names,
        create_default_registry,
    )
    for _proto_name in parsed.protocols:
        if _proto_name not in available_protocol_names():
            continue
        try:
            _selected_handler = create_default_registry([_proto_name]).get(_proto_name)
        except Exception:
            _selected_handler = None
        if _selected_handler is not None:
            _selected_handler.validate_cli_intent(parsed, parser, logger)


def _normalize_protocol_selection(raw, parser, valid_names):
    """Normalize and validate the multi-select ``--protocol`` values.

    *raw* is what argparse's ``action="append"`` produced: ``None`` (flag never
    given) or a list of strings, each of which may itself be comma-separated
    (``["tls,rc4", "ssh"]``). Returns an ordered, de-duplicated list of protocol
    names. The default (flag absent, or only empty tokens) collapses to
    ``["tls"]`` so the common single-protocol case is unchanged.

    Validation (all via ``parser.error``):
      * every token must be a known protocol name or a meta value (all/auto);
      * ``all``/``auto`` are standalone, never combined with a named protocol;
      * ``ssh``/``ipsec``/``mtproto`` are exclusive: never combined with any
        other *non-custom* protocol (only their own hooks install);
      * ``custom`` expands to every registered custom cipher (category
        ``custom_cipher``, e.g. rc4). Custom ciphers combine with anything
        except ``all``/``auto`` (including the exclusive protocols) and are
        ordered after the non-custom protocols so ``protocols[0]`` stays the
        primary protocol.
    """
    from friTap.protocols.registry import (
        CUSTOM_GROUP,
        custom_cipher_handlers,
        expand_custom_group,
        order_protocol_selection,
    )
    META = ("all", "auto")
    EXCLUSIVE = ("ssh", "ipsec", "mtproto")
    if not raw:
        return ["tls"]
    tokens = []
    for item in raw:
        for part in str(item).split(","):
            part = part.strip()
            if part:
                tokens.append(part)
    if not tokens:
        return ["tls"]
    known = set(valid_names) | set(META) | {CUSTOM_GROUP}
    unknown = [t for t in tokens if t not in known]
    if unknown:
        parser.error(
            "--protocol: unknown protocol(s): " + ", ".join(unknown) + "; "
            "choose from " + ", ".join(list(valid_names) + list(META) + [CUSTOM_GROUP])
        )
    # Every custom cipher (incl. upcoming ones selectable by explicit name)
    # classifies tokens; only the announced ones expand the `custom` group.
    cipher_handlers = custom_cipher_handlers(include_upcoming=True)
    all_cipher_names = [h.name for h in cipher_handlers]
    custom_ciphers = set(all_cipher_names)
    if CUSTOM_GROUP in tokens:
        group_names = [h.name for h in cipher_handlers if not getattr(h, "upcoming", False)]
        if not group_names:
            parser.error("--protocol custom: no custom ciphers available in this build")
        # Expand `custom` in place, then de-duplicate (order-preserving).
        selection = expand_custom_group(tokens, group_names)
    else:
        selection = list(dict.fromkeys(tokens))
    if len(selection) > 1:
        metas = [t for t in selection if t in META]
        if metas:
            parser.error(
                f"--protocol: '{metas[0]}' is a standalone meta-value and cannot "
                "be combined with other protocols."
            )
        # Custom ciphers ride along with any protocol, so exclusivity is only
        # checked among the non-custom (main) protocols.
        main_protocols = [t for t in selection if t not in custom_ciphers]
        exclusives = [t for t in main_protocols if t in EXCLUSIVE]
        if exclusives and len(main_protocols) > 1:
            parser.error(
                f"--protocol: '{exclusives[0]}' is exclusive and cannot be "
                "combined with other protocols."
            )
    # Keep the main protocol first: protocols[0] is the primary protocol.
    return order_protocol_selection(selection, all_cipher_names)


def _hex_text_or_none(data):
    """*data* as lowercase hex when it is hex text (whitespace ignored), else None."""
    try:
        text = "".join(data.decode("ascii").split())
    except UnicodeDecodeError:
        return None
    if not text or len(text) % 2:
        return None
    try:
        bytes.fromhex(text)
    except ValueError:
        return None
    return text.lower()


def _resolve_ms_rc4_ciphertext(value):
    """Resolve the ``--ms-rc4-ciphertext`` argument into a string.

    A leading ``@`` means the rest is a path whose contents are the sample. The
    file is read as bytes: hex text (whitespace ignored) is used as that hex,
    anything else is hex-encoded byte for byte (a text decode would corrupt
    binary samples). Other values are returned unchanged; inline normalisation
    stays in ``loader.apply_rc4_param_overrides`` so CLI and config agree.

    Raises ``ValueError`` with a user-facing message when the file is missing,
    unreadable or empty.
    """
    if not value or not isinstance(value, str) or not value.startswith("@"):
        return value
    path = value[1:]
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        raise ValueError(
            f"--ms-rc4-ciphertext: cannot read '{path}': {exc.strerror or exc}"
        ) from exc
    if not data:
        raise ValueError(f"--ms-rc4-ciphertext: file '{path}' is empty")
    return _hex_text_or_none(data) or data.hex()


_WINE_MODES = ("auto", "on", "off")


def _normalize_bare_wine_flag(argv):
    """Make a bare ``--wine`` mean ``--wine auto``.

    ``--wine`` takes an optional mode; without this, argparse would consume the
    following target (``fritap -s --wine app.exe``) as the mode and reject it.
    Tokens after a ``--`` separator belong to the target and are left untouched.
    """
    out = []
    for i, tok in enumerate(argv):
        if tok == "--":
            return out + list(argv[i:])
        out.append(tok)
        if tok == "--wine":
            nxt = argv[i + 1] if i + 1 < len(argv) else None
            if nxt is not None and nxt not in _WINE_MODES and not nxt.startswith("-"):
                out.append("auto")
    return out


def _maybe_prepend_wine(parsed, logger):
    """CLI-layer Wine synthesis.

    When a Windows target is given directly on Linux (e.g. ``fritap -s app.exe``),
    prepend the ``wine`` launcher so the rest of friTap sees a normal
    ``wine app.exe`` spawn command and the existing Wine detection/route applies.

    Controlled by ``--wine``: ``off`` disables synthesis; ``on`` forces it for any
    non-Wine spawn target; ``auto`` (default) treats the target as Windows when the
    file's magic is PE (``MZ``) or, when the file can't be read, when its name
    ends in ``.exe``. Linux host and spawn mode only; no-op if the command already
    starts with a Wine launcher.
    """
    import os
    import platform

    if platform.system() != "Linux" or not getattr(parsed, "spawn", False):
        return
    mode = getattr(parsed, "wine", "auto")
    if mode == "off":
        return

    argv = getattr(parsed, "exec_argv", None) or (
        [parsed.exec] if getattr(parsed, "exec", None) else []
    )
    if not argv:
        return
    first = argv[0]
    # Same launcher set SSL_Logger._target_is_wine uses for routing.
    if os.path.basename(first).lower() in WINE_BASENAMES:
        return  # already a wine command

    is_pe = False
    exists = os.path.isfile(first)
    if exists:
        try:
            with open(first, "rb") as fh:
                is_pe = fh.read(2) == b"MZ"
        except OSError:
            is_pe = False
    looks_exe = first.lower().endswith(".exe")

    if mode == "on":
        treat_as_wine = True
    else:  # auto: trust PE magic for an existing file, else the .exe suffix
        treat_as_wine = is_pe if exists else looks_exe
    if not treat_as_wine:
        return

    import shutil
    wine = shutil.which("wine") or "wine"
    parsed.exec_argv = [wine, *argv]
    parsed.exec = " ".join(parsed.exec_argv)
    why = "PE binary" if is_pe else ("'.exe' target" if looks_exe else "Wine forced (--wine on)")
    logger.info(
        "%s on Linux -> assuming Wine; running '%s' with GDB key extraction "
        "(override with --wine off).", why, parsed.exec,
    )


def _apply_decoder_isolation_flag(parsed):
    """--isolate-decoders: switch isolation on here and for child processes."""
    if not getattr(parsed, "isolate_decoders", False):
        return
    import os

    from .decoder_isolation import ISOLATE_DECODERS_ENV, enable_decoder_isolation
    enable_decoder_isolation()
    os.environ[ISOLATE_DECODERS_ENV] = "1"
