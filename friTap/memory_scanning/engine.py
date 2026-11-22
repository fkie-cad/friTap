#!/usr/bin/env python3

"""MemoryScanEngine: friTap's heap secret-scanner (``--memory-scan`` / ``-ms``).

Loads a separate Frida agent (``friTap/fritap_memscan.js``) that recovers secrets
by scanning the target's heap instead of hooking the TLS library. The agent is
host-driven: this engine calls ``configure(profile)`` once, then polls
``scanOnce()`` on a background thread. Findings arrive as ``send({type:'keylog'})``
messages and are republished as ``KeylogEvent(protocol="memscan")``.
``SSL_Logger.instrument()`` drives :meth:`start` / :meth:`stop` / :meth:`close`.
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

MS_BACKOFF_FACTOR = 2.0
MS_BACKOFF_CAP_SECONDS = 60.0

# The inter-scan wait is served in slices of at most this long on the stop Event.
# A stop is seen within one slice, and each slice boundary releases the GIL so the
# main thread (the only one that runs the SIGINT handler) can service Ctrl+C.
# Without it, intervals <= 0.3s starved the main thread (20+ SIGINTs ignored).
MS_STOP_POLL_SECONDS = 0.1

MS_MIN_YIELD_SECONDS = 0.05

# Poll-thread name of the in-process ("self") session. Only its unexpected end
# stops a memory-scan-only capture; the Windows lsass session must not.
MS_SELF_POLL_NAME = "fritap-memscan"

_here = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

_MEMSCAN_BUNDLE = os.path.join(_here, "fritap_memscan.js")


def _sidecar_column(value) -> str:
    """One whitespace-free sidecar column for *value*; ``-`` when absent (never the string "None", which offline would read as an id)."""
    if value is None:
        return "-"
    return "".join(str(value).split()) or "-"


def _kv_after(line: str, key: str) -> str:
    """Return the token starting with ``key`` minus that prefix ('' if absent)."""
    for tok in line.split():
        if tok.startswith(key):
            return tok[len(key):]
    return ""


def _parse_keylog_columns(line: str, tier: str) -> dict:
    """Parse a memory-scan keylog line into its JSON-summary columns.

    ``LABEL <client_random> <secret>`` is positional; ``RSA Session-ID:<sid> Master-Key:<master>``
    is parsed by key. The caller emits the raw line verbatim.
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
    """Injects the heap secret-scanner and drives its scan loop. Not a ``ScriptPlugin``: the core calls start/stop/close directly."""

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
        tls_secret_bundle_path: Optional[str] = None,
        emit_unconfirmed: bool = False,
        rc4_known_plaintext: Optional[str] = None,
        rc4_ciphertext: Optional[str] = None,
    ) -> None:
        self._scripts: List[Any] = []
        self._context: Optional["ScriptContext"] = None
        # Raw -ms value: a pattern file, or an engine name / profile id. The
        # resolver disambiguates (an existing file wins).
        self._patterns_path = patterns_path
        self._ms_arg = patterns_path
        self._interval = interval if interval and interval > 0 else 2.0
        self._profile_id = profile_id
        # The --protocol set selects the engine(s); defaults to TLS.
        self._protocols: List[str] = list(protocols) if protocols else ["tls"]
        # _protocols plus registry implications (signal -> tls), set in start().
        self._scan_protocols: List[str] = list(self._protocols)
        # -nl/--no-lsass: when False the lsass session is skipped.
        self._install_lsass_hook = install_lsass_hook
        self._source_cache: Optional[str] = None
        # Resolved profile list and its first element.
        self._profiles: List[dict] = []
        self._profile: Optional[dict] = None
        self._stop = threading.Event()
        self._poll_threads: List[threading.Thread] = []
        # A separate Frida session/script attached to lsass.exe (Windows only).
        self._lsass_session: Any = None
        self._lsass_script: Any = None
        # Sidecar for Schannel unpaired secrets (no memory-resident client_random),
        # joined to the pcap offline. None -> default path on first use.
        self._unpaired_path = unpaired_path
        self._unpaired_file: Any = None
        self._unpaired_lock = threading.Lock()
        # RC4 keys always go to a dedicated sidecar: `-ms rc4` leaves the protocol
        # set as ["tls"], so no rc4 keylog handler would exist otherwise.
        self._rc4_path = rc4_path
        self._rc4_file: Any = None
        self._rc4_lock = threading.Lock()
        # MTProto keys always go to a dedicated <stem>.mtproto.keylog, like RC4,
        # regardless of --protocol/-k.
        self._mtproto_path = mtproto_path
        self._mtproto_file: Any = None
        self._mtproto_lock = threading.Lock()
        # JSONL sidecar of ``tls_secret_bundle`` messages (both randoms plus the
        # application traffic secrets), so offline mid-stream decryption works for
        # flows with no ClientHello in the pcap. Supplements the NSS keylog.
        self._tls_secret_bundle_path = tls_secret_bundle_path
        self._tls_secret_bundle_file: Any = None
        self._tls_secret_bundle_lock = threading.Lock()
        # The heap scanner re-reads the same pooled socket every pass; dedup keeps
        # one record per bundle.
        self._tls_secret_bundle_seen: set = set()
        # The file is created lazily; the manifest advertises it only once written.
        self._tls_secret_bundle_written = False
        # --ms-emit-unconfirmed (default off): stamps ``emitUnconfirmed`` onto
        # mtproto profiles and lets _handle_unpaired persist unconfirmed candidates.
        self._emit_unconfirmed = bool(emit_unconfirmed)
        # RC4 oracles from --ms-rc4-known-plaintext / --ms-rc4-ciphertext (no SSPI
        # oracle on Android). Merged onto the rc4 profile in _configure_rpc.
        self._rc4_known_plaintext = rc4_known_plaintext
        self._rc4_ciphertext = rc4_ciphertext
        # Fired from the self session's poll thread when scanOnce() raises because
        # the agent script died (app killed/ANR'd) without a stop request.
        self._on_scan_ended: Optional[Callable[[], None]] = None

    def set_scan_ended_callback(self, callback: Optional[Callable[[], None]]) -> None:
        """Register a callback fired on the poll thread when the in-process scan ends unexpectedly; it must be thread-safe and quick."""
        self._on_scan_ended = callback

    @property
    def _e2e_requested(self) -> bool:
        """Whether Secret-Chat (E2E) scanning was requested (``telegram``, not ``mtproto``); opt-in because it sweeps the multi-GiB ART heap."""
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

    def start(self, context: "ScriptContext") -> None:
        """Resolve the engine(s) from the pattern database, then run one scan session per scan_target ("self" in the target, "lsass" in a separate session). Resolving first makes a bad pattern file fail loudly."""
        if not self.is_compatible_with(context.backend_name):
            logger.warning(
                "memory-scan: backend %s not in %s — skipping heap scanner",
                context.backend_name, self.supported_backends,
            )
            return
        self._context = context
        try:
            from ..protocols.registry import expand_protocols
            from .loader import (
                group_profiles_by_scan_target,
                load_database,
                select_profiles,
            )
            os_name = self._detect_target_os(context)
            database = load_database(None)
            # Expand implications (signal -> tls) so tls-tagged profiles (e.g. the
            # libsignal-net scudo one) are selected under `--protocol signal`.
            self._scan_protocols = sorted(expand_protocols(self._protocols))
            self._profiles = select_profiles(
                database, self._scan_protocols, os_name, self._ms_arg
            )
        except Exception as exc:  # noqa: BLE001 - surface a clear message, skip cleanly
            logger.error("memory-scan: failed to resolve pattern profile(s): %s", exc)
            return

        # No engine applies (e.g. `--protocol ssh -ms`): skip rather than inject
        # a scanner with nothing to look for.
        if not self._profiles:
            logger.info(
                "memory-scan: no scan engine for protocol(s) %s on %s — "
                "nothing to scan (skipping)",
                ", ".join(self._scan_protocols), os_name or "unknown platform",
            )
            return

        self._profile = self._profiles[0]
        grouped = group_profiles_by_scan_target(self._profiles)
        self._stop.clear()

        self_profiles = grouped.get("self")
        if self_profiles:
            self._configure_self_session(context, self_profiles)

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
        """Resolve the RPC surface, configure the agent and start polling; ``success_msg`` is logged between configure and poll start."""
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
        """Attach a second Frida session to lsass.exe (where Schannel keys live) and scan there; honours ``-nl/--no-lsass``."""
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
        # Resolve per-arch offsets here so the agent only reads profile["resolved"].
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
        """Configure one agent session with a profile list; return True on success."""
        profiles = self._apply_emit_unconfirmed(profiles)
        # mtproto = AUTH+OBF, telegram = AUTH+OBF+E2E (the heavy Dalvik tier).
        profiles = self._apply_e2e_scope(profiles)
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
        except Exception as exc:  # noqa: BLE001 - Frida RPC call
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
        """Best-effort target CPU arch as frida reports it, or None (falls back to the single-arch choice)."""
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
        """Return *profiles* with each schannel profile resolved under ``resolved``; others pass through."""
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
        """Return *profiles* with *transform* applied to those of *engine*; others pass through untouched."""
        return [transform(p) if p.get("engine") == engine else p for p in profiles]

    def _apply_emit_unconfirmed(self, profiles: List[dict]) -> List[dict]:
        """Stamp ``emitUnconfirmed=True`` onto MTProto profile copies when opted in.

        Safe because offline ``auth_key_id`` (low 8 bytes of SHA1(auth_key)) rejects wrong candidates; the cost is keylog noise.
        """
        if not self._emit_unconfirmed:
            return profiles
        return self._map_engine(
            profiles, "mtproto", lambda p: {**p, "emitUnconfirmed": True})

    def _apply_rc4_overrides(self, profiles: List[dict]) -> List[dict]:
        """Merge the CLI RC4 oracles into copies of rc4 profiles (the shared database is never mutated)."""
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
        """Disable the MTProto E2E tier (``C_art_secretchat_key``) in profile copies unless E2E was requested.

        It sweeps the multi-GiB ART/Dalvik heap and ANR'd the app on ``mtproto``-only runs.
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
        """Best-effort target OS (``windows|linux|android|macos|ios``) from frida, or None.

        None leaves ``["all"]`` profiles selectable; platform-pinned ones do not match.
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
        """Call scanOnce() on an exponential-backoff schedule (base interval while passes emit, up to ``MS_BACKOFF_CAP_SECONDS`` otherwise).

        If scanOnce raises while ``_stop`` is unset (agent destroyed), the self session calls ``_on_scan_ended``.
        """
        wait = self._interval
        while not self._stop.is_set():
            # Scans are not cancellable; a stop during the last wait must skip this one.
            if self._stop.is_set():
                return
            try:
                stats = rpc.scanOnce()
                emitted = stats.get("emitted", 0) if isinstance(stats, dict) else 0
                if logger.isEnabledFor(logging.DEBUG) and isinstance(stats, dict):
                    logger.debug(
                        "memory-scan: scan emitted=%s durationMs=%s",
                        stats.get("emitted"), stats.get("durationMs"),
                    )
                    # Full stats (per-tier funnels) diagnose silent zero-result runs.
                    logger.debug("memory-scan: full stats %s", stats)
                    # Concise BoringSSL anchor-locator funnel.
                    tier_b0 = stats.get("tierB0") if isinstance(stats, dict) else None
                    if isinstance(tier_b0, dict):
                        logger.debug(
                            "memory-scan: tierB0 candidates=%s validated=%s emitted=%s",
                            tier_b0.get("candidates"), tier_b0.get("validated"),
                            tier_b0.get("emitted"),
                        )
            except Exception as exc:  # noqa: BLE001 - target may have detached
                # Method-not-found means a stale fritap_memscan.js, not a detach.
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
            if emitted:
                wait = self._interval
            else:
                wait = min(wait * MS_BACKOFF_FACTOR, MS_BACKOFF_CAP_SECONDS)
            # Always leave a GIL-releasing gap, served in interruptible slices.
            if self._wait_between_scans(max(wait, MS_MIN_YIELD_SECONDS)):
                return

    def _wait_between_scans(self, seconds: float) -> bool:
        """Wait up to *seconds* in ``MS_STOP_POLL_SECONDS`` slices on the stop Event.

        Returns True as soon as a stop is requested, else False after the full wait.
        """
        remaining = seconds
        while remaining > 0:
            if self._stop.wait(min(remaining, MS_STOP_POLL_SECONDS)):
                return True
            remaining -= MS_STOP_POLL_SECONDS
        return self._stop.is_set()

    def _notify_scan_ended(self, name: str) -> None:
        """Fire the scan-ended callback, only for an unrequested end of the self session."""
        if name != MS_SELF_POLL_NAME or self._stop.is_set():
            return
        callback = self._on_scan_ended
        if callback is None:
            return
        try:
            callback()
        except Exception:  # noqa: BLE001 - a callback failure must not crash the thread
            logger.debug("memory-scan: scan-ended callback failed", exc_info=True)

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
            # MTPROTO_* labels go to the MTProto keylog; all others take the memscan path.
            if str(payload.get("label", "")).startswith("MTPROTO_"):
                self._publish_mtproto_finding(payload)
            else:
                self._publish_finding(payload)
        elif kind == "rc4_key":
            self._publish_rc4_key(payload)
        elif kind == "tls_secret_bundle":
            self._write_tls_secret_bundle(payload)
        elif kind == "log":
            level = str(payload.get("level", "info")).upper()
            logger.log(getattr(logging, level, logging.INFO),
                       "memory-scan: %s", payload.get("msg", ""))
        elif kind == "unpaired":
            self._handle_unpaired(payload)
        elif kind == "cachedump":
            # Schannel session_cache DUMP mode (session_id_at uncalibrated): log only.
            logger.info(
                "memory-scan: schannel cache-item dump (uncalibrated session_id) "
                "at %s (master %s…)",
                payload.get("cache_item", ""),
                str(payload.get("master", ""))[:16],
            )

    def _handle_unpaired(self, payload: dict) -> None:
        """Route an ``unpaired`` secret by ``kind``: Schannel secrets go to the sidecar for the offline correlator; BoringSSL ``orphan_session`` is only logged."""
        kind = str(payload.get("kind", ""))
        if kind.startswith("schannel_"):
            self._write_unpaired(payload)
            return
        # Unconfirmed MTProto candidates carry no key bytes, so they are recorded
        # as ``#`` comments (auth_key_id + address) that the decryptor ignores.
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
        """Record an unconfirmed mtproto candidate as a ``#`` comment (auth_key_id + heap address); only with ``--ms-emit-unconfirmed``."""
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
        # The parsed parts ride in `payload` so consumers don't re-split the line.
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
        """Turn an ``rc4_key`` agent message into a ``KeylogEvent(protocol="rc4")`` via :func:`rc4_keylog_spec.format_line`."""
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
        # Always written to the sidecar, even without --protocol rc4.
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

    def _resolve_unpaired_path(self) -> str:
        """Where Schannel unpaired secrets go (``<stem>.schannel.unpaired``), cached.

        Falls back to a file in the current directory.
        """
        if self._unpaired_path:
            return self._unpaired_path
        self._unpaired_path = "schannel_memscan.schannel.unpaired"
        return self._unpaired_path

    def _write_unpaired(self, payload: dict) -> None:
        """Append one unpaired Schannel secret to the sidecar.

        Columns: ``<kind> <secret_hex> <session_id_or_dash> <ssl_version> <group_or_dash>``.
        session_id is ``-`` (Schannel keeps no client_random near the key struct);
        ``group`` ties sibling TLS 1.3 secrets of one connection so the offline
        correlator can place EXPORTER_SECRET by elimination.
        """
        secret = str(payload.get("secret", "")).strip().lower()
        if not secret:
            return
        kind = str(payload.get("kind", "schannel")) or "schannel"
        session_id = _sidecar_column(payload.get("session_id"))
        ssl_version = payload.get("ssl_version", 0)
        try:
            ssl_version = int(ssl_version)
        except (TypeError, ValueError):
            ssl_version = 0
        group = _sidecar_column(payload.get("group"))
        line = f"{kind} {secret} {session_id} {ssl_version} {group}"
        path = self._resolve_unpaired_path()
        with self._unpaired_lock:
            try:
                if self._unpaired_file is None:
                    self._unpaired_file = open(path, "w", encoding="utf-8", newline="\n")
                    self._unpaired_file.write(
                        "# friTap Schannel memory-scan UNPAIRED secrets\n"
                        "#   <kind> <secret_hex> <session_id|-> <ssl_version> <group|->\n"
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

    def _resolve_rc4_path(self) -> str:
        """Where RC4 keys go (``<stem>.rc4.keylog``), cached; falls back to the current directory."""
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
                    from ..protocols.rc4_keylog_spec import HEADER_COMMENT
                    self._rc4_file.write(HEADER_COMMENT + "\n")
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

    def _publish_mtproto_finding(self, payload: dict) -> None:
        """Route an MTProto keylog message to the sidecar and the bus.

        The line is re-rendered through :mod:`mtproto_keylog_spec`, which drops malformed lines.
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
        # Only the bus emit needs the context; the sidecar write never does.
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
        """Where MTProto keys go (``<stem>.mtproto.keylog``), cached; falls back to the current directory."""
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

    # Bundle fields in stable order, all lowercase hex: randoms are 64 chars,
    # traffic secrets 64 or 96.
    _TLS_BUNDLE_FIELDS = (
        "client_random",
        "server_random",
        "client_traffic_secret_0",
        "server_traffic_secret_0",
        "exporter_secret",
    )

    def _resolve_tls_secret_bundle_path(self) -> str:
        """Where bundles go (``<stem>.tls_midstream.secrets.jsonl``), cached; falls back to the current directory."""
        if self._tls_secret_bundle_path:
            return self._tls_secret_bundle_path
        self._tls_secret_bundle_path = "tls_midstream_memscan.tls_midstream.secrets.jsonl"
        return self._tls_secret_bundle_path

    @staticmethod
    def _is_lower_hex(value: str, expected_lens: Optional[tuple] = None) -> bool:
        """True iff *value* is non-empty even-length lowercase hex (optionally sized)."""
        if not value or len(value) % 2 != 0:
            return False
        if expected_lens is not None and len(value) not in expected_lens:
            return False
        try:
            int(value, 16)
        except ValueError:
            return False
        return value == value.lower()

    def _bundle_record(self, payload: dict) -> Optional[dict]:
        """Validate a ``tls_secret_bundle`` payload into a leak-safe record, or None.

        Needs ``client_random`` plus one traffic secret (one binds a direction; some
        builds scrub ``server_random``); other fields become ``''`` when absent or invalid.
        """
        def _valid_field(field: str) -> str:
            value = str(payload.get(field, "")).strip().lower()
            expected = (64,) if field.endswith("random") else (64, 96)
            return value if self._is_lower_hex(value, expected) else ""

        client_random = _valid_field("client_random")
        client_secret = _valid_field("client_traffic_secret_0")
        server_secret = _valid_field("server_traffic_secret_0")
        if not client_random or not (client_secret or server_secret):
            return None
        return {
            "client_random": client_random,
            "server_random": _valid_field("server_random"),
            "client_traffic_secret_0": client_secret,
            "server_traffic_secret_0": server_secret,
            "exporter_secret": _valid_field("exporter_secret"),
        }

    def _write_tls_secret_bundle(self, payload: dict) -> None:
        """Append one validated, de-duplicated bundle to the JSONL sidecar (secrets only there; the JSON form cannot forge an ``RSA Session-ID:`` NSS line)."""
        record = self._bundle_record(payload)
        if record is None:
            logger.debug("memory-scan: dropping malformed tls_secret_bundle: %s",
                         {k: v for k, v in payload.items() if k != "ssl"})
            return
        dedup_key = (
            record.get("client_random", ""),
            record.get("client_traffic_secret_0", ""),
            record.get("server_traffic_secret_0", ""),
            record.get("exporter_secret", ""),
        )
        path = self._resolve_tls_secret_bundle_path()
        with self._tls_secret_bundle_lock:
            if dedup_key in self._tls_secret_bundle_seen:
                return
            try:
                import json
                if self._tls_secret_bundle_file is None:
                    self._tls_secret_bundle_file = open(
                        path, "w", encoding="utf-8", newline="\n")
                    logger.info("memory-scan: tls mid-stream secret bundles → %s", path)
                self._tls_secret_bundle_file.write(
                    json.dumps(record, separators=(",", ":")) + "\n")
                self._tls_secret_bundle_file.flush()
                self._tls_secret_bundle_seen.add(dedup_key)
                self._tls_secret_bundle_written = True
            except Exception:  # noqa: BLE001
                logger.debug("memory-scan: failed to write tls secret bundle",
                             exc_info=True)

    def _close_tls_secret_bundle(self) -> None:
        with self._tls_secret_bundle_lock:
            if self._tls_secret_bundle_file is not None:
                try:
                    self._tls_secret_bundle_file.close()
                except Exception:  # noqa: BLE001
                    logger.debug("memory-scan: failed to close tls secret-bundle sidecar",
                                 exc_info=True)
                self._tls_secret_bundle_file = None

    def tls_midstream_manifest_entry(self) -> dict:
        """``{"tls_midstream_secrets": <path>}`` once a bundle was written (the file is lazy), else ``{}``."""
        if self._tls_secret_bundle_written and self._tls_secret_bundle_path:
            return {"tls_midstream_secrets": self._tls_secret_bundle_path}
        return {}

    def intended_tls_secret_bundle_path(self) -> str:
        """The deterministic bundle path, valid before the first write so the reader matches the writer."""
        return self._resolve_tls_secret_bundle_path()

    def stop(self, context: "ScriptContext") -> None:
        """Stop the scan loop and unload the self-session script(s).

        Called by the core when the target process detaches.
        """
        self._stop.set()
        self._teardown_lsass_session(context)
        self._close_unpaired()
        self._close_rc4()
        self._close_mtproto()
        self._close_tls_secret_bundle()
        self._unload_scripts(context)

    def close(self) -> None:
        """Final teardown during core cleanup."""
        self._stop.set()
        self._teardown_lsass_session(self._context)
        self._close_unpaired()
        self._close_rc4()
        self._close_mtproto()
        self._close_tls_secret_bundle()
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

    def _load_script_bounded(self, context: "ScriptContext", script: Any) -> None:
        """Load *script* under the context timeout (``script.load()`` is not cancellable); raises ``BackendScriptLoadTimeout``."""
        try:
            context.backend.load_script(script, timeout=context.script_load_timeout)
        except BackendScriptLoadTimeout as exc:
            if not exc.breadcrumb:
                exc.breadcrumb = "memory-scan"
            raise

    def _route_message(self, message: dict, data: Any) -> None:
        """Route backend messages to on_script_message; never let it raise into Frida."""
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

    @staticmethod
    def _rpc(script: Any) -> Any:
        """Return the script RPC proxy, preferring the blocking ``exports_sync`` (Frida 17 splits it from async ``exports``)."""
        return getattr(script, "exports_sync", None) or getattr(script, "exports", None)
