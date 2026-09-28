#!/usr/bin/env python3

"""MemoryScanEngine — friTap's heap secret-scanner (the ``--memory-scan`` / ``-ms`` feature).

This is a first-class friTap capability, **not** a plugin. It loads a separate,
independently-injected Frida agent (``friTap/fritap_memscan.js``) that recovers
TLS secrets by scanning the target's heap memory, instead of hooking the TLS
library. The agent is *host-driven*: it exposes an RPC surface
(``configure(profile)``, ``scanOnce()``, ``needle()``) and this engine owns the
loop — it configures the agent once with a validated profile, then polls
``scanOnce()`` on a background thread. Recovered NSS keylog lines arrive as
``send({type:'keylog', line, ...})`` messages, which are republished on the
EventBus as ``KeylogEvent(protocol="memscan")`` (mirroring the
``--scan-keys-region`` path) so the shared keylog output handler, the JSON
handler and the TUI pick them up regardless of whether ``-k`` was given.

The engine is driven directly by the core (``SSL_Logger.instrument()`` calls
:meth:`start` / :meth:`stop` / :meth:`close`), and it is self-contained: it owns
its own script injection, message routing and teardown rather than inheriting
them from the plugin base classes. It remains reachable *through* the plugin
system via the thin :class:`friTap.memory_scanning.plugin.MemoryScanScriptPlugin`
adapter, which simply delegates its lifecycle to a ``MemoryScanEngine``.

This is complementary to friTap's normal capture: passed alone it is the only
agent loaded (the main TLS-hooking agent is skipped by ``instrument()``);
combined with ``-k``/``-p``/``-c`` it runs alongside them.
"""

from __future__ import annotations

import copy
import logging
import os
import threading
from typing import TYPE_CHECKING, Any, Callable, List, Optional

from ..backends.base import BackendScriptLoadTimeout

if TYPE_CHECKING:
    from ..plugins.script_context import ScriptContext

logger = logging.getLogger("friTap.memory_scanning.engine")

# Snapshot + exponential-backoff schedule for the scan poll loop. The first
# passes run at the configured base interval so keys land fast; when a pass finds
# nothing new the wait grows by MS_BACKOFF_FACTOR up to MS_BACKOFF_CAP_SECONDS,
# then resets to the base the moment a pass emits again. This keeps steady-state
# load off the target (the fixed 2s cadence over ~135 MB was ANR'ing Telegram)
# without losing coverage of keys that rotate as messages are sent/received.
MS_BACKOFF_FACTOR = 2.0
MS_BACKOFF_CAP_SECONDS = 60.0

# The poll-thread name of the in-process ("self") scan session. Only this
# session's unexpected termination ends a memory-scan-only capture (see
# _poll_loop / set_scan_ended_callback); the lsass session is Windows-side and
# must not tear down the main run.
MS_SELF_POLL_NAME = "fritap-memscan"

# Directory where the friTap package lives (for resolving the shipped bundle).
_here = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

# The compiled memory-scan agent bundle, shipped next to fritap_agent.js.
_MEMSCAN_BUNDLE = os.path.join(_here, "fritap_memscan.js")


def _kv_after(line: str, key: str) -> str:
    """Return the token starting with ``key`` minus that prefix ('' if absent)."""
    for tok in line.split():
        if tok.startswith(key):
            return tok[len(key):]
    return ""


def _parse_keylog_columns(line: str, tier: str) -> dict:
    """Parse a memory-scan keylog line into its JSON-summary columns.

    Two NSS line shapes flow through the scanner and need different columns:

    * standard secrets — ``LABEL <client_random> <secret>`` (``CLIENT_RANDOM`` and
      the ``*_TRAFFIC_SECRET_*`` family): populate label / client_random / secret;
    * the Schannel session-cache line — ``RSA Session-ID:<sid> Master-Key:<master>``
      (``tier == "schannel_session_cache"``): a positional split would mislabel the
      ``Session-ID:`` token as the client_random and ``Master-Key:`` as the secret,
      so parse the session id + master out of their ``key:value`` tokens instead.

    Only the JSON summary columns are affected; the raw keylog line (``key_data``)
    is emitted verbatim by the caller regardless of shape.
    """
    if tier == "schannel_session_cache" or line.startswith("RSA Session-ID:"):
        return {
            "label": "RSA",
            "client_random": None,  # session-cache masters have no client_random
            "secret": _kv_after(line, "Master-Key:"),
            "session_id": _kv_after(line, "Session-ID:"),
            "format": "rsa_session_cache",
        }
    parts = line.split(maxsplit=2)
    return {
        "label": parts[0] if parts else "",
        "client_random": parts[1] if len(parts) >= 3 else "",
        "secret": parts[2] if len(parts) >= 3 else "",
        "format": "nss",
    }


class MemoryScanEngine:
    """Injects the heap secret-scanner and drives its scan loop.

    A standalone, framework-agnostic engine — **not** a ``ScriptPlugin``. The
    core constructs one and drives its :meth:`start` / :meth:`stop` /
    :meth:`close` lifecycle directly. It owns its own script injection and
    message routing (previously inherited from the plugin base classes).
    """

    # Backends this engine can inject into (empty list = all). The heap scanner
    # is Frida-only, matching the historical plugin's ``supported_backends``.
    supported_backends: List[str] = ["frida"]

    def __init__(
        self,
        patterns_path: Optional[str] = None,
        interval: float = 2.0,
        profile_id: Optional[str] = None,
        protocols: Optional[List[str]] = None,
        install_lsass_hook: bool = True,
        unpaired_path: Optional[str] = None,
        rc4_path: Optional[str] = None,
        mtproto_path: Optional[str] = None,
        emit_unconfirmed: bool = False,
        rc4_known_plaintext: Optional[str] = None,
        rc4_ciphertext: Optional[str] = None,
    ) -> None:
        # Script bookkeeping + active context (previously provided by the
        # ScriptPlugin base class; the engine now owns them itself).
        self._scripts: List[Any] = []
        self._context: Optional["ScriptContext"] = None
        # ``patterns_path`` is the raw -ms value: a custom pattern FILE, or a
        # targeted engine name / profile id. The resolver disambiguates it (an
        # existing file wins, then a known engine/id), so it is carried verbatim.
        self._patterns_path = patterns_path
        self._ms_arg = patterns_path
        self._interval = interval if interval and interval > 0 else 2.0
        self._profile_id = profile_id
        # The selected --protocol set drives which engine(s) apply; default to
        # TLS so a plugin built without an explicit set behaves as before.
        self._protocols: List[str] = list(protocols) if protocols else ["tls"]
        # Honour -nl/--no-lsass: when False, the separate lsass session is skipped.
        self._install_lsass_hook = install_lsass_hook
        self._source_cache: Optional[str] = None
        # The resolved profile list (F3) and its first element (back-compat).
        self._profiles: List[dict] = []
        self._profile: Optional[dict] = None
        self._stop = threading.Event()
        self._poll_threads: List[threading.Thread] = []
        # A separate Frida session/script attached to lsass.exe (Windows only).
        self._lsass_session: Any = None
        self._lsass_script: Any = None
        # Where Schannel UNPAIRED secrets (TLS 1.2 master / TLS 1.3 secrets with
        # no memory-resident client_random) are written for the offline pcap
        # correlator (Workstream 5). None -> derived from the target on first use.
        self._unpaired_path = unpaired_path
        self._unpaired_file: Any = None
        self._unpaired_lock = threading.Lock()
        # RC4 keys recovered by the heap scanner are tagged protocol="rc4" for
        # JSON/consumers, but the keylog *file* must not depend on the user also
        # selecting --protocol rc4 (a targeted `-ms rc4` run leaves the protocol
        # set as ["tls"], so no rc4 keylog handler would exist). Mirroring the
        # unpaired sidecar, the plugin always writes recovered RC4 keys to its
        # own dedicated file so `-ms rc4` reliably produces output.
        self._rc4_path = rc4_path
        self._rc4_file: Any = None
        self._rc4_lock = threading.Lock()
        # MTProto (Telegram) keys recovered from the heap are tagged
        # protocol="mtproto" for JSON/keylog consumers, but - mirroring the RC4
        # sidecar - the engine ALWAYS writes them to its own dedicated
        # <stem>.mtproto.keylog file so `-ms mtproto` reliably produces a keylog
        # the offline MTProto decryptor can read, regardless of --protocol/-k.
        self._mtproto_path = mtproto_path
        self._mtproto_file: Any = None
        self._mtproto_lock = threading.Lock()
        # E4: opt-in (--ms-emit-unconfirmed, default OFF). When True we (a) stamp
        # ``emitUnconfirmed`` onto mtproto profiles so the agent emits heap key
        # candidates the auth_key_id oracle could NOT confirm as real keylog lines,
        # and (b) let _handle_unpaired persist any mtproto candidate it does see.
        self._emit_unconfirmed = bool(emit_unconfirmed)
        # RC4 oracles injected from the CLI (--ms-rc4-known-plaintext /
        # --ms-rc4-ciphertext). There is no SSPI oracle on Android, so these are
        # how a known-plaintext prefix (exact, zero-false-accept key test) and/or a
        # ciphertext sample (trial-decrypt scoring) reach the rc4 profile's params.
        # None (the default) leaves the profile untouched. Merged in _configure_rpc
        # via loader.apply_rc4_param_overrides, only onto the rc4 engine's profile.
        self._rc4_known_plaintext = rc4_known_plaintext
        self._rc4_ciphertext = rc4_ciphertext
        # Bottom-up "the scan ended on its own" callback. Invoked from the self
        # session's poll thread if scanOnce() raises because the agent script was
        # destroyed (e.g. the app was killed/ANR'd) WITHOUT us asking to stop.
        # The core wires this so a memory-scan-only capture can leave the
        # "capturing" state instead of hanging there forever. See _poll_loop.
        self._on_scan_ended: Optional[Callable[[], None]] = None

    def set_scan_ended_callback(self, callback: Optional[Callable[[], None]]) -> None:
        """Register a callback fired when the in-process scan ends unexpectedly.

        The callback runs on the scan poll thread, so it must be thread-safe and
        return quickly (``SSL_Logger.request_stop`` satisfies both).
        """
        self._on_scan_ended = callback

    @property
    def _e2e_requested(self) -> bool:
        """Whether Secret-Chat (E2E) scanning was requested for this run.

        E2E is the expensive MTProto tier (it sweeps the multi-GiB ART/Dalvik
        heap). It is opt-in via the ``telegram`` protocol/engine — ``mtproto``
        means normal traffic only (AUTH + OBF). ``--protocol telegram,mtproto`` is
        therefore the same as ``telegram``. See :meth:`_apply_e2e_scope`.
        """
        if "telegram" in (self._protocols or []):
            return True
        return self._ms_arg == "telegram"

    @property
    def name(self) -> str:
        return "memory-scan"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        src = self._patterns_path or "bundled default patterns"
        return f"Heap secret-scanner (--memory-scan) using {src}"

    def is_compatible_with(self, backend_name: str) -> bool:
        """Whether this engine can inject into *backend_name* (empty list = all)."""
        return not self.supported_backends or backend_name in self.supported_backends

    # ------------------------------------------------------------------
    # Script source
    # ------------------------------------------------------------------

    def get_script_source(self, context: "ScriptContext") -> str:
        """Read the compiled memory-scan agent bundle (cached)."""
        if self._source_cache is not None:
            return self._source_cache
        try:
            with open(_MEMSCAN_BUNDLE, encoding="utf-8", newline="\n") as f:
                self._source_cache = f.read()
                return self._source_cache
        except FileNotFoundError:
            logger.error(
                "Memory-scan agent bundle not found: %s — build it with "
                "'npm run build:memscan' (or dev/compile_agent.sh).",
                _MEMSCAN_BUNDLE,
            )
            return ""

    # ------------------------------------------------------------------
    # Instrumentation lifecycle
    # ------------------------------------------------------------------

    def start(self, context: "ScriptContext") -> None:
        """Resolve the engine(s), then run one scan session per scan_target.

        F3: which engine(s) run is driven by the selected ``--protocol`` set, the
        target platform and the optional ``-ms`` override, resolved from the
        central pattern database. Resolved profiles are grouped by their
        ``scan_target``: ``"self"`` profiles load into the injected target
        process (the historical path), ``"lsass"`` profiles into a separate
        Frida session attached to lsass.exe. Resolving BEFORE injecting anything
        keeps a bad pattern file / unknown engine failing loudly.
        """
        if not self.is_compatible_with(context.backend_name):
            logger.warning(
                "memory-scan: backend %s not in %s — skipping heap scanner",
                context.backend_name, self.supported_backends,
            )
            return
        # Store the active context so message handlers / teardown can reach the
        # backend and event bus (the ScriptPlugin base used to set this).
        self._context = context
        try:
            from .loader import (
                group_profiles_by_scan_target,
                load_database,
                select_profiles,
            )
            os_name = self._detect_target_os(context)
            database = load_database(None)
            self._profiles = select_profiles(
                database, self._protocols, os_name, self._ms_arg
            )
        except Exception as exc:  # noqa: BLE001 - surface a clear message, skip cleanly
            logger.error("memory-scan: failed to resolve pattern profile(s): %s", exc)
            return

        # No engine applies (e.g. `--protocol ssh -ms`, or a platform no profile
        # targets): no-op gracefully rather than injecting a scanner with nothing
        # to look for. INFO, not error — an empty result is a valid outcome.
        if not self._profiles:
            logger.info(
                "memory-scan: no scan engine for protocol(s) %s on %s — "
                "nothing to scan (skipping)",
                ", ".join(self._protocols), os_name or "unknown platform",
            )
            return

        self._profile = self._profiles[0]  # back-compat: first resolved profile
        grouped = group_profiles_by_scan_target(self._profiles)
        self._stop.clear()

        # scan_target == "self": the historical in-process scan. On Linux/Android
        # /macOS with the single shipped BoringSSL profile this is byte-for-byte
        # the old behaviour — one profile in a one-element list to configure().
        self_profiles = grouped.get("self")
        if self_profiles:
            self._configure_self_session(context, self_profiles)

        # scan_target == "lsass": a separate session attached to lsass.exe.
        lsass_profiles = grouped.get("lsass")
        if lsass_profiles:
            self._configure_lsass_session(context, lsass_profiles, os_name)

    def _configure_self_session(
        self, context: "ScriptContext", profiles: List[dict]
    ) -> None:
        """Inject the scanner into the target process and drive it."""
        source = self.get_script_source(context)
        if not source:
            return
        # Create the script, wire _route_message, load it under the timeout bound
        # (this is what the ScriptPlugin base used to do in on_instrument).
        script = context.backend.create_script(
            context.process, source, runtime=context.runtime)
        context.backend.on_message(script, self._route_message)
        self._load_script_bounded(context, script)
        self._scripts.append(script)
        self._drive_session(script, profiles, "self", MS_SELF_POLL_NAME)

    def _drive_session(
        self, script: Any, profiles: List[dict], where: str, poll_name: str,
        success_msg: Optional[str] = None,
    ) -> None:
        """Shared session-drive tail: resolve the RPC surface, configure, poll.

        Both the self and lsass paths end the same way once a script exists: get
        the RPC surface (bail with an error if the agent exposes none), configure
        it, and start polling on success. ``where`` names the session so the
        rpc-None message reads exactly as before; ``success_msg``, when given, is
        logged between a successful configure and the poll start (the lsass path's
        extra confirmation).
        """
        rpc = self._rpc(script)
        if rpc is None:
            label = "LSASS agent" if where == "lsass" else "agent"
            logger.error(
                "memory-scan: %s exposes no RPC surface — cannot scan", label)
            return
        if self._configure_rpc(rpc, profiles, where):
            if success_msg is not None:
                logger.info(success_msg)
            self._start_poll(rpc, poll_name)

    def _configure_lsass_session(
        self, context: "ScriptContext", profiles: List[dict], os_name: Optional[str]
    ) -> None:
        """Attach a separate Frida session to lsass.exe and drive the scan there.

        Mirrors friTap's existing LSASS mechanism (``get_pid_of_lsass`` +
        attach-a-second-session): the scanner bundle is loaded into lsass.exe
        rather than the injected target, because Schannel's master/session keys
        live in the LSA process, not the application. Honours ``-nl/--no-lsass``.
        """
        if os_name != "windows":
            logger.warning(
                "memory-scan: scan_target 'lsass' only applies on Windows; "
                "skipping %d lsass profile(s) on %s",
                len(profiles), os_name or "unknown platform",
            )
            return
        if not self._install_lsass_hook:
            logger.info(
                "memory-scan: LSASS hooking disabled (-nl/--no-lsass) — "
                "skipping %d lsass profile(s)", len(profiles),
            )
            return
        # Resolve per-arch Schannel offsets HERE, in Python, so the agent stays
        # data-driven (it reads profile["resolved"], never branches on arch). The
        # target arch is the frida-reported one for this device.
        profiles = self._resolve_schannel_arch(context, profiles)
        try:
            from ..fritap_utility import get_pid_of_lsass
            pid = get_pid_of_lsass()
            if pid is None:
                logger.warning(
                    "memory-scan: LSASS process not found — skipping lsass scan")
                return
            source = self.get_script_source(context)
            if not source:
                return
            session = context.backend.attach(context.device, str(pid))
            script = context.backend.create_script(
                session, source, runtime=context.runtime)
            context.backend.on_message(script, self._route_message)
            context.backend.load_script(
                script, timeout=context.script_load_timeout)
            self._lsass_session = session
            self._lsass_script = script
        except Exception as exc:  # noqa: BLE001 - a missing lsass must not crash the run
            logger.error("memory-scan: failed to attach LSASS session: %s", exc)
            return

        self._drive_session(
            script, profiles, "lsass", "fritap-memscan-lsass",
            success_msg=(
                "memory-scan: attached separate LSASS session (pid %s) for "
                "%d profile(s)" % (pid, len(profiles))
            ),
        )

    def _configure_rpc(self, rpc: Any, profiles: List[dict], where: str) -> bool:
        """Configure one agent session with a profile list; return True on success.

        F2's ``configure()`` accepts a single profile OR a list, so the resolved
        per-scan_target list is passed straight through.
        """
        # E4: apply the emit-unconfirmed opt-in to mtproto profiles here so BOTH
        # the self-session and the lsass-session paths get it uniformly.
        profiles = self._apply_emit_unconfirmed(profiles)
        # Scope MTProto to the requested key types: mtproto = AUTH+OBF only,
        # telegram = AUTH+OBF+E2E. Disables the heavy E2E (Dalvik) tier otherwise.
        profiles = self._apply_e2e_scope(profiles)
        # Merge the CLI-injected RC4 oracles (known-plaintext / ciphertext) into the
        # rc4 profile's params, only onto rc4 profiles, on a shallow copy.
        profiles = self._apply_rc4_overrides(profiles)
        if any(p.get("engine") == "mtproto" for p in profiles):
            logger.info(
                "memory-scan: mtproto scope = %s",
                "AUTH+OBF+E2E"
                if self._e2e_requested
                else "AUTH+OBF (E2E tier disabled; select --protocol telegram "
                     "to include Secret-Chat keys)",
            )
        try:
            result = rpc.configure(profiles)
        except Exception as exc:  # noqa: BLE001
            logger.error("memory-scan: configure() [%s] failed: %s", where, exc)
            return False
        if isinstance(result, dict):
            if not result.get("ok", False):
                logger.error(
                    "memory-scan: configure() [%s] rejected profile(s): %s",
                    where, result.get("error"),
                )
                return False
            logger.info(
                "memory-scan: [%s] %d profile(s) configured (%s ranges, %s bytes) "
                "— scanning every %.1fs",
                where, len(profiles), result.get("ranges"),
                result.get("rangeBytes"), self._interval,
            )
        return True

    def _start_poll(self, rpc: Any, name: str) -> None:
        """Start a background poll loop for one agent session."""
        thread = threading.Thread(
            target=self._poll_loop, args=(rpc, name), name=name, daemon=True,
        )
        self._poll_threads.append(thread)
        thread.start()

    def _detect_target_arch(self, context: "ScriptContext") -> Optional[str]:
        """Best-effort target CPU arch as frida reports it (``arm64``/``x64``/…).

        Reads the same device system parameters :meth:`_detect_target_os` uses.
        Any failure returns None, which leaves arch selection to the single-arch
        fallback in :func:`select_schannel_offsets`.
        """
        try:
            params = context.backend.query_system_parameters(context.device)
        except Exception:  # noqa: BLE001
            return None
        if not isinstance(params, dict):
            return None
        arch = params.get("arch")
        return str(arch) if arch else None

    def _resolve_schannel_arch(
        self, context: "ScriptContext", profiles: List[dict]
    ) -> List[dict]:
        """Return the profiles with each schannel profile's arch offsets resolved.

        Non-schannel profiles pass through untouched. A schannel profile is
        replaced with a copy carrying its arch-appropriate offset set under
        ``resolved`` (see :func:`memory_scanning.loader.resolve_schannel_arch`).
        """
        from .loader import resolve_schannel_arch
        arch = self._detect_target_arch(context)
        out: List[dict] = []
        for profile in profiles:
            if profile.get("engine") == "schannel":
                try:
                    out.append(resolve_schannel_arch(profile, arch))
                    logger.info(
                        "memory-scan: resolved schannel offsets for arch %s "
                        "(profile %s)", arch or "auto", profile.get("id"))
                except Exception as exc:  # noqa: BLE001
                    logger.error(
                        "memory-scan: cannot resolve schannel offsets for arch "
                        "%s: %s — skipping profile %s",
                        arch, exc, profile.get("id"))
            else:
                out.append(profile)
        return out

    @staticmethod
    def _map_engine(
        profiles: List[dict], engine: str, transform: Callable[[dict], dict],
    ) -> List[dict]:
        """Return *profiles* with *transform* applied to each profile of *engine*.

        Profiles of every other engine pass through untouched (same objects).
        """
        return [transform(p) if p.get("engine") == engine else p for p in profiles]

    def _apply_emit_unconfirmed(self, profiles: List[dict]) -> List[dict]:
        """Stamp ``emitUnconfirmed=True`` onto MTProto profiles when opted in.

        The agent's mtproto engine reads ``profile.emitUnconfirmed`` (default
        False) to decide whether to emit heap key candidates the auth_key_id
        oracle could NOT confirm. We only ever set it True, only on mtproto
        profiles, and on a shallow COPY so the shared pattern-database objects are
        never mutated. Non-mtproto profiles pass through untouched.

        Safe as an opt-in because, offline, ``auth_key_id = SHA1(auth_key)`` low 8
        bytes is computable: a wrong candidate simply matches no record (harmless)
        while a real one recovers messages — the only cost is extra keylog noise.
        """
        if not self._emit_unconfirmed:
            return profiles
        return self._map_engine(
            profiles, "mtproto", lambda p: {**p, "emitUnconfirmed": True})

    def _apply_rc4_overrides(self, profiles: List[dict]) -> List[dict]:
        """Merge the CLI RC4 oracles into rc4 profiles' params, when provided.

        Mirrors :meth:`_apply_emit_unconfirmed`: only ever touches the ``rc4``
        engine, only when an override is actually set, and on a shallow COPY (with
        a copied ``params`` dict) so the shared pattern-database objects are never
        mutated. Non-rc4 profiles pass through untouched, and a run with neither
        oracle set returns ``profiles`` unchanged (behaviour-preserving default).

        There is no SSPI ciphertext oracle on Android, so this is how a known-
        plaintext prefix (an exact, zero-false-accept key test) and/or a
        ciphertext sample reach the agent — see
        :func:`memory_scanning.loader.apply_rc4_param_overrides`, which normalises
        each value to hex and re-validates the merged params.
        """
        if self._rc4_known_plaintext is None and self._rc4_ciphertext is None:
            return profiles
        from .loader import apply_rc4_param_overrides

        def _override(profile: dict) -> dict:
            profile_copy = {**profile, "params": dict(profile.get("params", {}))}
            return apply_rc4_param_overrides(
                profile_copy,
                known_plaintext=self._rc4_known_plaintext,
                ciphertext_sample=self._rc4_ciphertext,
            )

        return self._map_engine(profiles, "rc4", _override)

    def _apply_e2e_scope(self, profiles: List[dict]) -> List[dict]:
        """Disable the MTProto E2E (Secret-Chat) tier unless E2E was requested.

        ``mtproto`` scans normal Telegram traffic (AUTH cloud-chat keys + OBF
        transport keys); ``telegram`` adds Secret-Chat (E2E) keys. E2E is Tier C
        (``C_art_secretchat_key``), which sweeps the multi-GiB ART/Dalvik heap and
        is the dominant scan cost — leaving it on for an ``mtproto``-only run both
        scanned keys the user did not ask for and drove the passes long enough to
        ANR the app.

        The agent already gates Tier C on ``profile.tiers.C_art_secretchat_key.enabled``
        (it returns before enumerating the ART heap), so scoping is a pure
        Python profile mutation: when E2E is NOT requested we hand the agent a copy
        of each mtproto profile with that tier disabled. AUTH (Tiers A/B) and OBF
        (Tier E) are untouched and run for both modes. The shared pattern database
        is never mutated — the copy is deep enough to isolate the tier dict.
        """
        if self._e2e_requested:
            return profiles

        def _disable_e2e_tier(profile: dict) -> dict:
            tiers = profile.get("tiers")
            if not (isinstance(tiers, dict)
                    and isinstance(tiers.get("C_art_secretchat_key"), dict)):
                return profile
            scoped = copy.deepcopy(profile)
            scoped["tiers"]["C_art_secretchat_key"]["enabled"] = False
            return scoped

        return self._map_engine(profiles, "mtproto", _disable_e2e_tier)

    def _detect_target_os(self, context: "ScriptContext") -> Optional[str]:
        """Best-effort target OS as a friTap platform string, or None.

        Reads the frida device's system parameters (the same source
        ``android.py`` uses for arch) and normalises the reported os id /
        platform onto ``windows | linux | android | macos | ios``. Any failure
        returns None, which leaves ``["all"]`` profiles selectable while a
        platform-pinned profile simply does not match.
        """
        from .loader import normalize_os_name
        try:
            params = context.backend.query_system_parameters(context.device)
        except Exception:  # noqa: BLE001
            return None
        if not isinstance(params, dict):
            return None
        os_field = params.get("os")
        os_id = os_field.get("id") if isinstance(os_field, dict) else None
        return normalize_os_name(os_id or params.get("platform"))

    def _poll_loop(self, rpc: Any, name: str = MS_SELF_POLL_NAME) -> None:
        """Call scanOnce() on a snapshot + exponential-backoff schedule.

        The first passes run at the base interval so the first keys land fast;
        while passes keep finding new keys the wait stays at the base, and once a
        pass emits nothing it grows geometrically up to ``MS_BACKOFF_CAP_SECONDS``.
        This keeps steady-state scan load off the target (the old fixed 2s cadence
        over ~135 MB — with 5–22s passes — left the app no idle time and ANR'd it)
        while still catching keys that rotate as messages flow.

        On an UNEXPECTED end (scanOnce raises because the agent script was
        destroyed — e.g. the app was killed/ANR'd — while ``_stop`` was NOT set),
        the in-process session invokes ``_on_scan_ended`` so a memory-scan-only
        capture can leave the "capturing" state instead of hanging forever.
        """
        wait = self._interval
        while not self._stop.is_set():
            try:
                stats = rpc.scanOnce()
                emitted = stats.get("emitted", 0) if isinstance(stats, dict) else 0
                if logger.isEnabledFor(logging.DEBUG) and isinstance(stats, dict):
                    logger.debug(
                        "memory-scan: scan emitted=%s durationMs=%s",
                        stats.get("emitted"), stats.get("durationMs"),
                    )
                    # Engines may return a rich per-scan funnel beyond the generic
                    # emitted/durationMs (e.g. the mtproto engine's per-tier
                    # state/candidates/confirmed, dataOffsetHits, roundTripByOffset).
                    # Dump the full stats object so a silent zero-result run (e.g. an
                    # uncalibrated build) is diagnosable for ANY engine, with no
                    # per-engine branch.
                    logger.debug("memory-scan: full stats %s", stats)
            except Exception as exc:  # noqa: BLE001 - target may have detached
                # A method-not-found RPCException is not a detach: it means the loaded
                # memory-scan bundle does not export scanOnce under a name the host can
                # reach (a stale friTap/fritap_memscan.js — the agent must export
                # `scanOnce`, and the current source does). Surface that as an actionable
                # warning rather than a silent debug line, so it is not mistaken for the
                # target simply going away.
                if "unable to find method" in str(exc).lower():
                    logger.warning(
                        "memory-scan: agent has no scanOnce export (%s) — the loaded "
                        "fritap_memscan.js is stale; rebuild it with "
                        "`./dev/compile_agent.sh ms` (or `npm run build:memscan`).",
                        exc,
                    )
                else:
                    logger.debug("memory-scan: scanOnce() ended: %s", exc)
                self._notify_scan_ended(name)
                return
            # Snapshot + backoff: reset to base when a pass finds new keys,
            # otherwise grow the wait geometrically up to the cap.
            if emitted:
                wait = self._interval
            else:
                wait = min(wait * MS_BACKOFF_FACTOR, MS_BACKOFF_CAP_SECONDS)
            self._stop.wait(wait)

    def _notify_scan_ended(self, name: str) -> None:
        """Fire the scan-ended callback for an UNEXPECTED end of the self session.

        Only the in-process ("self") session ending, and only when we did not ask
        to stop (``_stop`` unset), should tear a capture down — the lsass session
        is a Windows-side extra and a requested stop already drives teardown.
        """
        if name != MS_SELF_POLL_NAME or self._stop.is_set():
            return
        callback = self._on_scan_ended
        if callback is None:
            return
        try:
            callback()
        except Exception:  # noqa: BLE001 - a callback failure must not crash the thread
            logger.debug("memory-scan: scan-ended callback failed", exc_info=True)

    # ------------------------------------------------------------------
    # Messaging
    # ------------------------------------------------------------------

    def on_script_message(self, message: dict, data: Any) -> None:
        """Translate agent messages into EventBus events / log lines."""
        if message.get("type") == "error":
            logger.error("memory-scan agent error: %s", message)
            return
        payload = message.get("payload")
        if not isinstance(payload, dict):
            return
        kind = payload.get("type")
        if kind == "keylog":
            # MTProto keys arrive as keylog messages carrying a `label`
            # (MTPROTO_AUTH_KEY / MTPROTO_E2E_KEY) and a fully-formed line; route
            # them to the MTProto keylog the offline decryptor reads. Every other
            # keylog message (boringssl secrets, schannel session-cache) has no
            # MTProto label and takes the standard memscan path.
            if str(payload.get("label", "")).startswith("MTPROTO_"):
                self._publish_mtproto_finding(payload)
            else:
                self._publish_finding(payload)
        elif kind == "rc4_key":
            self._publish_rc4_key(payload)
        elif kind == "log":
            level = str(payload.get("level", "info")).upper()
            logger.log(getattr(logging, level, logging.INFO),
                       "memory-scan: %s", payload.get("msg", ""))
        elif kind == "unpaired":
            self._handle_unpaired(payload)
        elif kind == "cachedump":
            # Schannel session_cache tier in DUMP mode (session_id_at uncalibrated):
            # the agent dumps cache-item bytes so an operator can calibrate the
            # session-id offset offline. Surface where it landed, don't emit keys.
            logger.info(
                "memory-scan: schannel cache-item dump (uncalibrated session_id) "
                "at %s (master %s…)",
                payload.get("cache_item", ""),
                str(payload.get("master", ""))[:16],
            )

    def _handle_unpaired(self, payload: dict) -> None:
        """Route an ``unpaired`` secret by its ``kind``.

        BoringSSL Tier C (``orphan_session``) has no client_random and no offline
        correlator, so it is only logged. Schannel unpaired secrets
        (``schannel_tls12_master`` / ``schannel_tls13_secret``) DO have an offline
        correlator — Workstream 5 joins them to the pcap's client_random — so they
        are written to a dedicated sidecar in a stable, machine-readable format.
        """
        kind = str(payload.get("kind", ""))
        if kind.startswith("schannel_"):
            self._write_unpaired(payload)
            return
        # E4(b): MTProto unconfirmed candidates (auth_key / e2e keys the oracle
        # could not close). The agent only sends these as ``unpaired`` when
        # emitUnconfirmed is OFF (with it ON it emits full keylog lines instead,
        # see _apply_emit_unconfirmed), but we still honour the same opt-in here so
        # a candidate that does arrive is persisted for a follow-up key hunt rather
        # than silently logged. The unpaired payload carries no key bytes, so we
        # record it as a ``#`` comment candidate (auth_key_id + address) in the
        # .mtproto.keylog — a comment the decryptor's parser ignores, harmless yet
        # keeping the exact search term to feed the heap scanner next time.
        if kind in ("authkey_unconfirmed", "e2e_unconfirmed"):
            if self._emit_unconfirmed:
                self._write_mtproto_candidate(payload)
                return
            logger.info(
                "memory-scan: unpaired mtproto %s candidate id=%s (pass "
                "--ms-emit-unconfirmed to record it)",
                kind, payload.get("keyId", ""),
            )
            return
        logger.info(
            "memory-scan: unpaired %s secret (no client_random, not written to "
            "keylog): %s",
            kind or "orphan", payload.get("secret", ""),
        )

    def _write_mtproto_candidate(self, payload: dict) -> None:
        """Record one UNCONFIRMED mtproto candidate as a comment in the sidecar.

        The candidate has no key bytes (the oracle never closed it), so we write a
        ``#``-prefixed line the keylog parser skips. It preserves the auth_key_id /
        fingerprint and its heap address so a later targeted scan can go find the
        real key. Only reached when ``--ms-emit-unconfirmed`` is set.
        """
        kind = str(payload.get("kind", "mtproto_unconfirmed"))
        key_id = str(payload.get("keyId", "")).strip() or "-"
        addr = str(payload.get("addr", "")).strip() or "-"
        entropy = payload.get("entropy", "")
        self._write_mtproto_line(
            f"# UNCONFIRMED {kind} id={key_id} addr={addr} entropy={entropy}"
        )

    def _publish_finding(self, payload: dict) -> None:
        line = payload.get("line", "")
        if not line or self._context is None:
            return
        # Route through the shared keylog pipeline as a tagged KeylogEvent
        # (protocol="memscan"), mirroring the --scan-keys-region path: the
        # MemoryScanKeylogFormatter writes the line and the TUI/JSON handlers
        # recognise the tag. The parsed parts ride in `payload` so consumers
        # don't re-split the line.
        from ..events import KeylogEvent
        tier = str(payload.get("tier", ""))
        parsed = _parse_keylog_columns(line, tier)
        event = KeylogEvent(
            protocol="memscan",
            key_data=line,
            payload={
                **parsed,
                "tier": tier,
                "source": str(payload.get("source", "")),
            },
        )
        try:
            self._context.event_bus.emit(event)
        except Exception:  # noqa: BLE001
            logger.debug("memory-scan: failed to emit finding", exc_info=True)

    def _publish_rc4_key(self, payload: dict) -> None:
        """Turn an ``rc4_key`` agent message into a ``KeylogEvent(protocol="rc4")``.

        The RC4 memory-scan engine recovers a key (``memscan-trial``) or a post-KSA
        S-box state (``memscan-sbox``). The line is built via the canonical
        :func:`rc4_keylog_spec.format_line`, so it lands in the ``.rc4`` keylog file
        through :class:`Rc4KeylogFormatter` exactly like a hooked RC4 key.
        """
        if self._context is None:
            return
        from ..protocols import rc4_keylog_spec as spec
        key = str(payload.get("key", ""))
        key_len = payload.get("key_len")
        source = str(payload.get("source", ""))
        direction = str(payload.get("direction", spec.DIR_UNKNOWN))
        assoc = str(payload.get("assoc", "-"))
        line = spec.format_line(
            key=key, key_len=key_len, source=source,
            direction=direction, assoc=assoc,
        )
        if not line:
            logger.debug("memory-scan: dropping malformed rc4_key message: %s", payload)
            return
        # Always write to the dedicated RC4 sidecar so the key is never lost when
        # the run did not also select --protocol rc4 (see __init__ note).
        self._write_rc4_line(line)
        from ..events import KeylogEvent
        event = KeylogEvent(
            protocol="rc4",
            key_data=line,
            payload={
                "key": key,
                "key_len": key_len,
                "source": source,
                "direction": direction,
                "assoc": assoc,
            },
        )
        try:
            self._context.event_bus.emit(event)
        except Exception:  # noqa: BLE001
            logger.debug("memory-scan: failed to emit rc4 key", exc_info=True)

    # ------------------------------------------------------------------
    # Schannel unpaired sidecar (Workstream 5 consumes this)
    # ------------------------------------------------------------------

    def _resolve_unpaired_path(self) -> str:
        """Where Schannel unpaired secrets are written; derived once, then cached.

        Prefers the path handed in at construction (co-located with the memory-scan
        keylog as ``<stem>.schannel.unpaired``). Falls back to a file in the current
        directory so the sidecar is always written even without other output flags.
        """
        if self._unpaired_path:
            return self._unpaired_path
        self._unpaired_path = "schannel_memscan.schannel.unpaired"
        return self._unpaired_path

    def _write_unpaired(self, payload: dict) -> None:
        """Append one unpaired Schannel secret to the sidecar, stable columns.

        Format (single-space-separated, one record per line)::

            <kind> <secret_hex> <session_id_or_dash> <ssl_version>

        e.g. ``schannel_tls12_master aabb…(96 hex) - 771``. ``session_id`` is
        always ``-`` for these (Schannel does not store the client_random near the
        key struct); the four columns are fixed so Workstream 5's offline
        correlator can split each line without ambiguity.
        """
        secret = str(payload.get("secret", "")).strip().lower()
        if not secret:
            return
        kind = str(payload.get("kind", "schannel")) or "schannel"
        session_id = str(payload.get("session_id", "")).strip() or "-"
        ssl_version = payload.get("ssl_version", 0)
        try:
            ssl_version = int(ssl_version)
        except (TypeError, ValueError):
            ssl_version = 0
        line = f"{kind} {secret} {session_id} {ssl_version}"
        path = self._resolve_unpaired_path()
        with self._unpaired_lock:
            try:
                if self._unpaired_file is None:
                    self._unpaired_file = open(path, "w", encoding="utf-8", newline="\n")
                    self._unpaired_file.write(
                        "# friTap Schannel memory-scan UNPAIRED secrets\n"
                        "#   <kind> <secret_hex> <session_id|-> <ssl_version>\n"
                    )
                    logger.info("memory-scan: schannel unpaired secrets → %s", path)
                self._unpaired_file.write(line + "\n")
                self._unpaired_file.flush()
            except Exception:  # noqa: BLE001
                logger.debug("memory-scan: failed to write unpaired secret",
                             exc_info=True)

    def _close_unpaired(self) -> None:
        with self._unpaired_lock:
            if self._unpaired_file is not None:
                try:
                    self._unpaired_file.close()
                except Exception:  # noqa: BLE001
                    logger.debug("memory-scan: failed to close unpaired sidecar",
                                 exc_info=True)
                self._unpaired_file = None

    # ------------------------------------------------------------------
    # RC4 memory-scan keylog sidecar
    # ------------------------------------------------------------------

    def _resolve_rc4_path(self) -> str:
        """Where RC4 keys recovered from the heap are written; cached on first use.

        Prefers the path handed in at construction (co-located with the memory-scan
        keylog as ``<stem>.rc4.keylog``); falls back to a file in the current
        directory so `-ms rc4` always writes recovered keys regardless of
        ``--protocol``/``-k``.
        """
        if self._rc4_path:
            return self._rc4_path
        self._rc4_path = "rc4_memscan.rc4.keylog"
        return self._rc4_path

    def _write_rc4_line(self, line: str) -> None:
        """Append one ``RC4_KEY …`` line to the dedicated RC4 sidecar (leak-safe)."""
        if not line:
            return
        path = self._resolve_rc4_path()
        with self._rc4_lock:
            try:
                if self._rc4_file is None:
                    self._rc4_file = open(path, "w", encoding="utf-8", newline="\n")
                    self._rc4_file.write(
                        "# friTap RC4 memory-scan recovered keys\n"
                        "#   RC4_KEY <key_hex> <key_len> <source> <direction> <assoc>\n"
                    )
                    logger.info("memory-scan: rc4 keys → %s", path)
                self._rc4_file.write(line + "\n")
                self._rc4_file.flush()
            except Exception:  # noqa: BLE001
                logger.debug("memory-scan: failed to write rc4 key", exc_info=True)

    def _close_rc4(self) -> None:
        with self._rc4_lock:
            if self._rc4_file is not None:
                try:
                    self._rc4_file.close()
                except Exception:  # noqa: BLE001
                    logger.debug("memory-scan: failed to close rc4 sidecar",
                                 exc_info=True)
                self._rc4_file = None

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    def _publish_mtproto_finding(self, payload: dict) -> None:
        """Route an MTProto keylog message to the .mtproto.keylog sidecar + bus.

        The agent sends the fully-formed keylog line plus its label; we re-render
        it through :mod:`mtproto_keylog_spec` (canonical form + a last-chance
        validation that drops a malformed line rather than poisoning the keylog),
        write it to the dedicated sidecar so ``-ms mtproto`` always produces a
        decryptable file, and emit a ``KeylogEvent(protocol="mtproto")`` so it also
        lands in the split ``-k`` keylog / JSON when ``--protocol mtproto|telegram``
        is selected.
        """
        raw = str(payload.get("line", ""))
        if not raw:
            return
        from ..protocols import mtproto_keylog_spec as spec
        line = None
        auth = spec.parse_line(raw)
        if auth is not None:
            line = spec.format_line(
                dc_id=auth.dc_id, auth_key_id=auth.auth_key_id.hex(),
                auth_key=auth.auth_key.hex(), key_type=auth.key_type,
            )
        else:
            e2e = spec.parse_e2e_line(raw)
            if e2e is not None:
                line = spec.format_e2e_line(
                    key_fingerprint=e2e.key_fingerprint.hex(),
                    shared_key=e2e.shared_key.hex(), chat_id=e2e.chat_id,
                )
            else:
                obf = spec.parse_obf_line(raw)
                if obf is not None:
                    line = spec.format_obf_line(
                        key_out=obf.key_out.hex(), iv_out=obf.iv_out.hex(),
                        key_in=obf.key_in.hex(), iv_in=obf.iv_in.hex(),
                        num_out=obf.num_out, num_in=obf.num_in,
                        endpoint=obf.endpoint,
                    )
        if not line:
            logger.debug("memory-scan: dropping malformed mtproto keylog line: %s", raw)
            return
        self._write_mtproto_line(line)
        # The sidecar write above is the always-on guarantee for `-ms mtproto`
        # and needs no run context. The bus emit below (which feeds the split
        # `-k` keylog / JSON output) does need the context, so gate only that —
        # never the file write.
        if self._context is None:
            return
        from ..events import KeylogEvent
        event = KeylogEvent(
            protocol="mtproto",
            key_data=line,
            payload={
                "label": str(payload.get("label", "")),
                "tier": str(payload.get("tier", "")),
                "source": str(payload.get("source", "")),
                "key_id": str(payload.get("keyId", "")),
            },
        )
        try:
            self._context.event_bus.emit(event)
        except Exception:  # noqa: BLE001
            logger.debug("memory-scan: failed to emit mtproto key", exc_info=True)

    def _resolve_mtproto_path(self) -> str:
        """Where MTProto keys recovered from the heap are written; cached on first use.

        Prefers the path handed in at construction (co-located with the memory-scan
        keylog as ``<stem>.mtproto.keylog``); falls back to a file in the current
        directory so ``-ms mtproto`` always writes recovered keys regardless of
        ``--protocol``/``-k``.
        """
        if self._mtproto_path:
            return self._mtproto_path
        self._mtproto_path = "mtproto_memscan.mtproto.keylog"
        return self._mtproto_path

    def _write_mtproto_line(self, line: str) -> None:
        """Append one ``MTPROTO_* ...`` line to the dedicated MTProto sidecar (leak-safe)."""
        if not line:
            return
        path = self._resolve_mtproto_path()
        with self._mtproto_lock:
            try:
                if self._mtproto_file is None:
                    self._mtproto_file = open(path, "w", encoding="utf-8", newline="\n")
                    from ..protocols.mtproto_keylog_spec import HEADER_COMMENT
                    self._mtproto_file.write(HEADER_COMMENT + "\n")
                    logger.info("memory-scan: mtproto keys \u2192 %s", path)
                self._mtproto_file.write(line + "\n")
                self._mtproto_file.flush()
            except Exception:  # noqa: BLE001
                logger.debug("memory-scan: failed to write mtproto key", exc_info=True)

    def _close_mtproto(self) -> None:
        with self._mtproto_lock:
            if self._mtproto_file is not None:
                try:
                    self._mtproto_file.close()
                except Exception:  # noqa: BLE001
                    logger.debug("memory-scan: failed to close mtproto sidecar",
                                 exc_info=True)
                self._mtproto_file = None

    def stop(self, context: "ScriptContext") -> None:
        """Stop the scan loop and unload the self-session script(s).

        Called by the core when the target process detaches. Mirrors the old
        ``on_detach_process`` (which ended in ``ScriptPlugin`` unloading scripts).
        """
        self._stop.set()
        self._teardown_lsass_session(context)
        self._close_unpaired()
        self._close_rc4()
        self._close_mtproto()
        self._unload_scripts(context)

    def close(self) -> None:
        """Final teardown during core cleanup (mirrors the old ``on_unload``)."""
        self._stop.set()
        self._teardown_lsass_session(self._context)
        self._close_unpaired()
        self._close_rc4()
        self._close_mtproto()
        if self._context is not None:
            self._unload_scripts(self._context)
        self._scripts.clear()
        self._context = None

    def _teardown_lsass_session(self, context: "Optional[ScriptContext]") -> None:
        """Unload the lsass script and detach its separate session, if any."""
        if self._lsass_script is not None and context is not None:
            try:
                context.backend.unload_script(self._lsass_script)
            except Exception:  # noqa: BLE001
                logger.debug("memory-scan: failed to unload LSASS script",
                             exc_info=True)
        self._lsass_script = None
        if self._lsass_session is not None:
            try:
                self._lsass_session.detach()
            except Exception:  # noqa: BLE001
                logger.debug("memory-scan: failed to detach LSASS session",
                             exc_info=True)
        self._lsass_session = None

    # ------------------------------------------------------------------
    # Script injection helpers (owned by the engine; formerly ScriptPlugin's)
    # ------------------------------------------------------------------

    def _load_script_bounded(self, context: "ScriptContext", script: Any) -> None:
        """Load *script* under the timeout bound carried by *context*.

        The scanner bundle's top-level code can wedge exactly like the main
        agent's can, and Frida's ``script.load()`` is not cancellable. Without a
        bound a bad bundle hangs friTap forever with no diagnostic; with one it
        becomes a ``BackendScriptLoadTimeout`` carrying a breadcrumb naming the
        engine, so the caller can log which script wedged.
        """
        try:
            context.backend.load_script(script, timeout=context.script_load_timeout)
        except BackendScriptLoadTimeout as exc:
            if not exc.breadcrumb:
                exc.breadcrumb = "memory-scan"
            raise

    def _route_message(self, message: dict, data: Any) -> None:
        """Trampoline: route backend messages to on_script_message, guarded."""
        try:
            self.on_script_message(message, data)
        except Exception:  # noqa: BLE001
            logger.exception("memory-scan: on_script_message raised")

    def _unload_scripts(self, context: "Optional[ScriptContext]") -> None:
        """Unload all tracked self-session scripts via the backend."""
        if context is None:
            self._scripts.clear()
            return
        for script in self._scripts:
            try:
                context.backend.unload_script(script)
            except Exception:  # noqa: BLE001
                logger.debug("memory-scan: failed to unload script", exc_info=True)
        self._scripts.clear()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _rpc(script: Any) -> Any:
        """Return the script's RPC proxy, preferring the blocking variant.

        Frida 17 splits the proxy into ``exports_sync`` (blocking) and
        ``exports`` (async). We need blocking calls so ``configure`` and
        ``scanOnce`` return real values rather than coroutines.
        """
        return getattr(script, "exports_sync", None) or getattr(script, "exports", None)
