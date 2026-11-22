"""Wine targets for :class:`SSL_Logger`: Wine detection, the GDB-based key
extractor route and the Frida route with a host-side process watcher.

The host class owns the state. Names tests patch on ``ssl_logger_core`` are read
through ``_core()`` at call time so the patches take effect.
"""

import functools
import os
import re
import subprocess
import threading
import time

from ..backends.base import BackendName
from .ssl_logger_state import core_module as _core

# Module-level so the CLI layer can share it without going through the patchable class.
WINE_BASENAMES = ("wine", "wine64", "wine32", "wine-preloader", "wine64-preloader")


class WineMixin:
    """Wine detection and both Wine capture routes."""

    _WINE_BASENAMES = WINE_BASENAMES

    def _target_is_wine(self) -> bool:
        """Whether the argv[0] basename of :meth:`_wine_target_argv` is a Wine launcher."""
        argv = self._wine_target_argv()
        if not argv:
            return False
        import os as _os
        return _os.path.basename(argv[0]).lower() in self._WINE_BASENAMES

    def _wine_target_argv(self) -> list:
        """``target_argv``, else ``target_app`` shlex-split (whitespace split on an unbalanced quote)."""
        if self.target_argv:
            return list(self.target_argv)
        app = self.target_app or ""
        import shlex
        try:
            return shlex.split(app, posix=True)
        except ValueError:
            return app.split()

    def _pid_is_wine(self, pid) -> bool:
        """Whether ``pid``'s mapped memory looks like Wine (attach mode, where argv has no launcher)."""
        try:
            with open(f"/proc/{int(pid)}/maps") as handle:
                data = handle.read().lower()
        except (OSError, ValueError):
            return False
        markers = (
            "wine-preloader", "wine64-preloader", "/wine/", "/wine64",
            "ntdll.dll.so", "ntdll.so",
        )
        return any(marker in data for marker in markers)

    def _resolve_wine_attach_pid(self):
        """Resolve an attach target to a numeric PID for the gdb extractor.

        A non-numeric name is matched as a literal substring of /proc cmdlines (not
        a `pgrep -f` regex, where ``.`` is a metacharacter), preferring a Wine-looking
        process over a short-lived launcher. A ``wine <exe>`` command never appears
        verbatim in a running app's cmdline, so Wine targets retry with the exe path
        and basename.
        """
        if self.pid:
            return self.pid
        app = (self.target_app or "").strip()
        if app.isdigit():
            return int(app)
        if not app:
            return None
        procs = list(self._iter_proc_cmdlines())  # one snapshot for all needles
        wine_cache = {}

        def is_wine(pid):
            if pid not in wine_cache:
                wine_cache[pid] = self._pid_is_wine(pid)
            return wine_cache[pid]

        wine_pid, fallback = self._find_proc_by_cmdline(
            procs, lambda cmdline: app in cmdline, is_wine,
        )
        if wine_pid is not None:
            return wine_pid
        for needle in self._wine_exe_needles(app):
            wine_pid, _ = self._find_proc_by_cmdline(
                procs, self._cmdline_matcher(needle), is_wine,
            )
            if wine_pid is not None:
                return wine_pid
        return fallback

    @staticmethod
    def _find_proc_by_cmdline(procs, matches, is_wine):
        """``(wine_pid, fallback_pid)``: the first matching proc *is_wine* accepts, and the first of any kind."""
        fallback = None
        for pid, cmdline in procs:
            if not matches(cmdline):
                continue
            if is_wine(pid):
                return int(pid), fallback
            fallback = fallback or int(pid)
        return None, fallback

    @staticmethod
    def _path_basename(path):
        """Last component of a Windows or POSIX *path*."""
        return re.split(r"[\\/]", path)[-1]

    @classmethod
    def _cmdline_matcher(cls, needle):
        """Predicate for an exe *needle*: a path matches as a substring, a bare basename only
        as a whole token's basename (case-insensitive), so ``a.exe`` skips ``data.exe``."""
        if re.search(r"[\\/]", needle):
            return lambda cmdline: needle in cmdline
        wanted = needle.lower()
        return lambda cmdline: any(
            cls._path_basename(token).lower() == wanted for token in cmdline.split()
        )

    def _wine_exe_needles(self, app):
        """Exe path and basename of a ``wine <exe>`` target for the attach retry; empty otherwise."""
        if not self._target_is_wine():
            return []
        exe = self._wine_target_exe()
        if exe is None:
            return []
        basename = self._path_basename(exe)
        return [n for n in dict.fromkeys((exe, basename)) if n and n != app]

    def _wine_target_exe(self):
        """First ``.exe`` argument after the launcher (skipping e.g. ``start /unix``), else None."""
        for arg in self._wine_target_argv()[1:]:
            if arg.lower().endswith(".exe"):
                return arg
        return None

    @staticmethod
    def _wine_extractor_module():
        """The ``agent_gdb.wine.wine_key_extract`` module.

        A source checkout that was never installed gets the repo root added to
        ``sys.path`` so ``agent_gdb`` imports; ImportError if still missing.
        """
        import importlib
        name = "agent_gdb.wine.wine_key_extract"
        try:
            return importlib.import_module(name)
        except ImportError:
            import sys as _sys
            repo_root = os.path.dirname(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            )
            if repo_root not in _sys.path:
                _sys.path.insert(0, repo_root)
            return importlib.import_module(name)

    @classmethod
    def _wine_pattern_translator(cls):
        """The ``agent_gdb.wine.pattern_translate`` module."""
        import importlib
        cls._wine_extractor_module()
        return importlib.import_module("agent_gdb.wine.pattern_translate")

    def _user_patterns_path(self):
        """The ``--patterns`` path, or None."""
        return getattr(self._config.hooking, "patterns", None)

    def _wine_gdb_patterns_file(self):
        """``--patterns`` in the flat format the gdb script reads (v2 files go to a temp file), else None."""
        user_path = self._user_patterns_path()
        if not user_path:
            return None
        return self._wine_pattern_translator().wine_patterns_for_gdb(
            user_path, self.logger,
        )

    def _discard_wine_gdb_patterns(self, gdb_patterns):
        """Remove a temp file made by :meth:`_wine_gdb_patterns_file`."""
        if gdb_patterns:
            self._wine_pattern_translator().discard_translated_patterns(
                gdb_patterns, self._user_patterns_path(),
            )

    @classmethod
    def _iter_proc_cmdlines(cls):
        """``(pid, cmdline)`` per readable /proc process, minus friTap and its ancestors.

        A ``sudo fritap ... wine app.exe`` parent carries the target string itself.
        """
        wke = cls._wine_extractor_module()
        return wke.iter_proc_cmdlines(exclude=wke.own_process_lineage())

    def _should_use_wine_gdb(self) -> bool:
        """True for a local Linux Wine target to hand to the GDB key extractor instead of Frida.

        Frida's Wine support is experimental, and gdb and Frida both need ptrace, so
        gdb drives the target alone. Local Linux host and target only.
        """
        import platform
        if platform.system() != "Linux":
            return False
        if self.mobile or self.device_id or self.host:
            return False

        mode = self.wine_mode
        if mode == "off":
            return False
        if mode == "on":
            return True  # user forces the GDB route

        # auto: an explicit `--backend frida` wants the Frida path; don't hijack it.
        if self.backend_explicit and self._config.backend == BackendName.FRIDA:
            return False

        try:
            if self._target_is_wine():
                return True
        except Exception:
            return False
        if not self.spawn:  # attach mode: inspect the live process maps
            return self._attach_target_is_wine()
        return False

    def _attach_target_is_wine(self) -> bool:
        """Attach mode: does the resolved target look like Wine? Caches the PID for the gdb session.

        A missing extractor means False, so a non-Wine attach never fails here.
        """
        try:
            pid = self._resolve_wine_attach_pid()
        except ImportError as exc:
            self.logger.debug("Wine extractor unavailable, skipping Wine check: %s", exc)
            return False
        self._wine_attach_pid = pid
        return pid is not None and self._pid_is_wine(pid)

    def _wine_chromium_modules(self):
        """Chromium-family BoringSSL modules (libcef.dll, chrome.dll, Electron .exe, ...), resolved once.

        Spawn searches next to the launched exe; attach reads the target's mappings.
        """
        cached = getattr(self, "_wine_chromium_cache", None)
        if cached is not None:
            return cached
        mods = []
        try:
            from ..wine_chromium import find_chromium_modules, wine_path_to_unix
            if self.spawn:
                exe = self._wine_target_exe()
                if exe:
                    unix = wine_path_to_unix(exe, os.environ.get("WINEPREFIX"))
                    if os.path.isfile(unix):
                        mods = find_chromium_modules(unix)
            else:
                pid = getattr(self, "_wine_attach_pid", None) or self._resolve_wine_attach_pid()
                if pid is not None:
                    mods = self._chromium_modules_in_maps(pid)
        except Exception as exc:
            self.logger.debug("Chromium module discovery failed: %s", exc)
        self._wine_chromium_cache = mods
        return mods

    @staticmethod
    def _chromium_modules_in_maps(pid):
        """Chromium-family BoringSSL module files mapped into ``pid``."""
        from ..wine_chromium import CHROMIUM_MODULE_NAMES, ELECTRON_EXE_MIN_SIZE
        try:
            with open(f"/proc/{int(pid)}/maps") as fh:
                lines = fh.read().splitlines()
        except (OSError, ValueError):
            return []
        found = []
        for line in lines:
            parts = line.split(None, 5)
            if len(parts) < 6:
                continue
            path = parts[5]
            name = os.path.basename(path).lower()
            if path in found:
                continue
            if name in CHROMIUM_MODULE_NAMES:
                found.append(path)
            elif name.endswith(".exe"):
                try:
                    if os.path.getsize(path) >= ELECTRON_EXE_MIN_SIZE:
                        found.append(path)
                except OSError:
                    pass
        return found

    def _should_use_wine_frida_watch(self) -> bool:
        """True for a local Linux Wine target to run on Frida with the process watcher, not GDB.

        Chosen in ``--wine auto`` for Chromium-embedded BoringSSL (CEF / Chrome /
        Electron / Qt WebEngine): they do TLS in a child process, which only this
        route follows, and their key hook is the agent's tier-4 anchor locator. An
        explicit ``--backend frida`` also lands here (Frida cannot spawn the ``wine``
        shell wrapper). ``--wine on`` forces GDB, ``--wine off`` the plain Frida path.
        """
        import platform
        if platform.system() != "Linux":
            return False
        if self.mobile or self.device_id or self.host:
            return False
        if self.wine_mode != "auto" or self._config.backend != BackendName.FRIDA:
            return False
        try:
            is_wine = self._target_is_wine() if self.spawn else self._attach_target_is_wine()
        except Exception:
            return False
        if not is_wine:
            return False
        if self.backend_explicit:
            return True
        return bool(self._wine_chromium_modules())

    def _run_wine_frida_watch_session(self, own_message_handler=None):
        """Run a Wine target on Frida, following its processes from the host.

        Spawn: Wine launches normally and a
        :class:`~friTap.wine_process_watcher.WineProcessWatcher` hands every new app
        process of the prefix (browser, network service, helpers; not renderers/GPU)
        to the instrument worker. Attach: the target is instrumented, plus later
        processes with ``--enable_child_gating``. Chromium modules are pre-resolved
        on the host so no process has to scan.
        """
        from ..wine_chromium import chromium_offsets, merge_offsets
        from ..wine_process_watcher import (
            WineProcessWatcher,
            current_pids,
            process_wine_prefix,
        )
        wke = self._wine_extractor_module()

        self.logger.info(
            "Wine target with Chromium-embedded BoringSSL — using Frida with a "
            "Wine process watcher (child processes are followed)."
            if self._wine_chromium_modules() else
            "Wine target — using Frida with a Wine process watcher."
        )
        if not self.experimental:
            # The Wine agent (PE-module rows, LdrLoadDll hook) needs --experimental.
            self._config.hooking.experimental = True
        # Lean load: the watcher attaches a new network-service process before its
        # first TLS, so the agent must skip the full-module Memory.scan sweep.
        # Drives the `lean_wine` key in the config batch.
        self._wine_lean = True
        # The slim bundle (frida-java/objc bridges excluded) injects reliably into a
        # freshly created Chromium network service, early enough for its first TLS
        # handshakes; the full bundle broke the young service about half the time.
        # FRITAP_AGENT_BUNDLE still wins (checked first in _resolve_agent_bundle_path).
        wine_bundle = os.path.join(_core().here, "fritap_agent_wine.js")
        if os.path.isfile(wine_bundle):
            self.agent_script = "fritap_agent_wine.js"
            self._resolved_agent_bundle = wine_bundle
            self.logger.info("Using slim Wine agent bundle: %s", wine_bundle)
        else:
            self.logger.warning(
                "Slim Wine agent bundle not found (%s); using the full bundle — "
                "early network-service capture may be unreliable. Rebuild with "
                "./dev/compile_agent.sh.", wine_bundle)
        if os.geteuid() != 0 and wke.ptrace_scope() != 0:
            self.logger.warning(
                "kernel.yama.ptrace_scope=%d: Wine re-parents the app's processes, so "
                "attaching to them needs ptrace_scope=0 (sudo sysctl "
                "kernel.yama.ptrace_scope=0) or root.", wke.ptrace_scope(),
            )

        mods = self._wine_chromium_modules()
        if mods:
            extra = chromium_offsets(mods)
            for name, entry in extra.items():
                self.logger.info(
                    "Pre-resolved ssl_log_secret in %s at rva %s",
                    name, entry["ssl_log_secret"]["address"],
                )
            missing = [m for m in mods if os.path.basename(m) not in extra]
            for path in missing:
                self.logger.info("No ssl_log_secret pre-resolved for %s; the agent will scan it", path)
            self.offsets_data = merge_offsets(self.offsets_data, extra)

        if self.device is None:
            self.device = self._backend.get_device()
        self.connect_live()
        self._setup_live_scan()
        self._start_consumer_thread()
        self._start_instrument_thread()

        def on_new(pid, label):
            self.logger.info("Wine process %s (pid %d): instrumenting", label, pid)
            self._enqueue_instrumentation(
                pid, f"Wine process {label}", label, resume=False,
            )

        launcher = None
        if self.spawn:
            argv = self._wine_target_argv()
            rest = argv[1:] if argv else []
            if not rest:
                self.logger.error(
                    "Wine spawn target has no executable (expected e.g. `wine app.exe`)."
                )
                self._done_event.set()
                return None, None
            run_as = wke.sudo_invoker()
            prefix_problem = wke.wine_prefix_problem(run_as)
            if prefix_problem:
                self.logger.error("%s", prefix_problem)
                self._done_event.set()
                return None, None
            home = run_as.home if run_as is not None else os.path.expanduser("~")
            prefix = os.environ.get("WINEPREFIX") or os.path.join(home, ".wine")
            # settle_seconds=0: attach the instant a network-service process is ready;
            # a settle would miss a one-shot startup handshake.
            watcher = WineProcessWatcher(on_new, prefix=prefix, exclude=current_pids(),
                                         settle_seconds=0.0)
            self._wine_watcher = watcher
            watcher.start()
            launcher = subprocess.Popen(
                [argv[0], *rest], start_new_session=True,
                **wke._run_as_popen_kwargs(run_as, os.environ),
            )
            self._track_wine_proc(launcher)
        else:
            pid = getattr(self, "_wine_attach_pid", None) or self._resolve_wine_attach_pid()
            if pid is None:
                self.logger.error(
                    "Could not determine a PID to attach to for Wine target %r.",
                    self.target_app,
                )
                self._done_event.set()
                return None, None
            self.pid = int(pid)
            watcher = None
            if self.enable_child_gating:
                watcher = WineProcessWatcher(
                    on_new, prefix=process_wine_prefix(pid), exclude=current_pids(),
                    settle_seconds=0.0,
                )
                self._wine_watcher = watcher
                watcher.start()
            # The running target is instrumented directly (past TLS is unrecoverable);
            # the watcher attaches its future network-service children early.
            on_new(int(pid), "attach target")
        self._wine_watcher = watcher
        self._wine_watch_monitor(launcher, watcher, attach_pid=None if self.spawn else self.pid)
        return None, None

    def _wine_watch_monitor(self, launcher, watcher, attach_pid=None):
        """Finish once the Wine app is gone: launcher exited and no instrumented process alive (spawn), or target and followed processes exited (attach)."""
        def alive_targets():
            alive = watcher.alive_reported() if watcher is not None else set()
            if attach_pid is not None and os.path.exists(f"/proc/{attach_pid}"):
                alive.add(attach_pid)
            return alive

        def _monitor():
            idle = 0
            while self.running and not self._done_event.is_set():
                time.sleep(1.0)
                launcher_alive = launcher is not None and launcher.poll() is None
                if launcher_alive or alive_targets():
                    idle = 0
                    continue
                idle += 1
                if idle >= 3:
                    self.logger.info("All Wine app processes exited; finishing.")
                    if watcher is not None:
                        watcher.stop()
                    self.request_stop()
                    self._wine_watch_finish()
                    return

        threading.Thread(target=_monitor, daemon=True, name="fritap-wine-monitor").start()

    def _wine_watch_finish(self):
        """Flush and signal completion for the watcher route, enough for the CLI wait loop."""
        try:
            self.finish_fritap()
        except Exception as exc:
            self.logger.debug("finish_fritap after Wine watch: %s", exc)
        self._done_event.set()

    def _run_wine_gdb_session(self, own_message_handler=None):
        """Run GDB-based TLS key extraction for a Wine target (no Frida).

        Arguments are validated synchronously so a bad target is reported before
        returning; the blocking gdb session then runs on a daemon thread, because
        start_fritap_session must return promptly (``wait_for_completion`` blocks on
        ``_done_event``; api.py expects a quick return). Only keys are extracted, no
        plaintext. Returns ``(None, None)`` per the ``start_session`` contract. The
        gdb/Wine process is tracked so :meth:`cleanup` can stop it (see
        ``_terminate_wine_gdb``).
        """
        wke = self._wine_extractor_module()

        self.logger.info(
            "Wine target detected on Linux — using the GDB-based key extractor "
            "(Frida injection skipped)."
        )

        self._log_wine_output_support()

        keylog = self.keylog
        if not keylog:
            keylog = os.path.abspath("wine_sslkeys.log")
            self.logger.warning("No keylog file given (-k); writing keys to %s", keylog)
        else:
            self.logger.info("Logging Wine TLS keys to %s", keylog)
        # The full-capture finalize embeds these keys (DSB); gdb appends, so only
        # bytes past the current size belong to this run.
        self._wine_keylog_path = keylog
        self._wine_keylog_offset = self._file_size(keylog)

        if self.spawn:
            # Launch Wine normally and attach: gdb-spawning Wine deadlocks its cold
            # boot on the wow64 layout. Needs kernel.yama.ptrace_scope=0 (see docs).
            argv = self._wine_target_argv()
            rest = argv[1:] if argv else []
            if not rest:
                self.logger.error(
                    "Wine spawn target has no executable (expected e.g. `wine app.exe`)."
                )
                self._done_event.set()
                return None, None
            # Wine refuses a prefix it does not own, so under sudo it runs as the invoker.
            run_as = wke.sudo_invoker()
            if run_as is not None:
                self.logger.info(
                    "Running as root via sudo; launching Wine as %s (uid %d) so it can use "
                    "that user's prefix.", run_as.user, run_as.uid,
                )
            prefix_problem = wke.wine_prefix_problem(run_as)
            if prefix_problem:
                self.logger.error("%s", prefix_problem)
                self._done_event.set()
                return None, None
            gdb_run_as = self._wine_gdb_run_as(run_as, keylog)
            gdb_patterns = self._wine_gdb_patterns_file()
            work = functools.partial(
                wke.launch_and_attach,
                wine_cmd=argv[0],
                program=rest[0],
                program_args=rest[1:],
                keylog=keylog,
                patterns=gdb_patterns,
                verbose=self.verbose,
                logger=self.logger,
                on_process=self._track_wine_proc,
                run_as=run_as,
                gdb_run_as=gdb_run_as,
            )
        else:
            attach = getattr(self, "_wine_attach_pid", None)
            if attach is None:
                attach = self._resolve_wine_attach_pid()
            if attach is None:
                self.logger.error(
                    "Could not determine a PID to attach to for Wine target %r.",
                    self.target_app,
                )
                self._log_wine_attach_hint()
                self._done_event.set()
                return None, None
            gdb_run_as = self._wine_gdb_run_as(
                wke.sudo_invoker(), keylog, target_pid=attach,
            )
            gdb_patterns = self._wine_gdb_patterns_file()
            work = functools.partial(
                wke.run_wine_key_extraction,
                attach=str(attach),
                keylog=keylog,
                patterns=gdb_patterns,
                verbose=self.verbose,
                on_process=self._track_wine_proc,
                run_as=gdb_run_as,
            )

        def _runner():
            reason = "Wine GDB key extraction finished"
            try:
                rc = work()
                reason = f"Wine GDB key extraction finished (gdb exit {rc})"
                self.logger.info("%s. Keylog: %s", reason, keylog)
            except Exception as exc:
                reason = f"Wine GDB key extraction failed: {exc}"
                self.logger.error("%s", reason)
            finally:
                self._discard_wine_gdb_patterns(gdb_patterns)
                self._finish_wine_session(reason)

        self._wine_thread = threading.Thread(
            target=_runner, name="fritap-wine-gdb", daemon=True
        )
        self._wine_thread.start()
        return None, None

    def _log_wine_output_support(self):
        """Tell the user which outputs the Wine GDB path serves.

        A full capture (-p FILE -f) works (keys are embedded at finalize); plaintext
        outputs need the Frida agent.
        """
        if self.full_capture:
            self.logger.info(
                "Full packet capture is active; the TLS keys for it come from the "
                "GDB extractor (embedded as a DSB when writing .pcapng)."
            )
        plaintext_pcap = self.pcap_name and not self.full_capture
        if plaintext_pcap or self.live or self.payload_modification or self.socket_trace:
            self.logger.warning(
                "Plaintext/pcap capture is not currently supported for Wine "
                "targets; only TLS key extraction (keylog) is available. For a "
                "full packet capture use -p <file> -f, or capture the keys with "
                "-k and decrypt the traffic in Wireshark."
            )

    def _log_wine_attach_hint(self):
        """Explain a failed attach whose target looks like a Wine launch command."""
        if not self._target_is_wine():
            return
        self.logger.error(
            "Hint: %r looks like a Wine launch command, but friTap ran in attach "
            "mode because -s/--spawn was not given.", self.target_app,
        )
        self.logger.error(
            "  -> To launch it under friTap: fritap -s -k keys.log wine app.exe"
        )
        self.logger.error(
            "  -> Or start the app first and attach by name: fritap -k keys.log app.exe"
        )

    def _wine_gdb_run_as(self, invoker, keylog, target_pid=None):
        """The sudo *invoker* to run gdb as (least privilege), or None for root.

        gdb drops privileges only when that can work (Yama scope, target ids, script
        and keylog access; see ``unprivileged_gdb_blocker``), else stays root and
        logs why. None when not running via sudo.
        """
        if invoker is None:
            return None
        wke = self._wine_extractor_module()
        reason = wke.unprivileged_gdb_blocker(invoker, keylog, target_pid=target_pid)
        if reason:
            self.logger.info("Keeping gdb as root: %s", reason)
            return None
        self.logger.info(
            "Running gdb as %s (uid %d); kernel.yama.ptrace_scope=0 allows an "
            "unprivileged attach.", invoker.user, invoker.uid,
        )
        return invoker

    def _finish_wine_session(self, reason):
        """End a self-finished Wine GDB session via :meth:`_end_session`.

        The shared teardown gives a full capture its rename, DSB and manifest.
        Skipped if a teardown already ran; ``_done_event`` is always set.
        """
        try:
            if not getattr(self, "_cleanup_done", False):
                self._end_session(reason)
        except Exception as exc:
            self.logger.error("Finalizing the Wine GDB session failed: %s", exc)
        finally:
            self._done_event.set()

    def _wine_keylog_lines(self):
        """Valid NSS keylog lines this session's gdb extractor wrote (past ``_wine_keylog_offset``), deduplicated in order.

        Comments, garbage and an unreadable file yield nothing.
        """
        path = getattr(self, "_wine_keylog_path", None)
        if not path:
            return []
        from ..offline.tls.keylog import parse_strict_nss_line
        try:
            text = self._read_keylog_since(path, getattr(self, "_wine_keylog_offset", 0))
        except OSError:
            return []
        entries = filter(None, map(parse_strict_nss_line, text.splitlines()))
        return list(dict.fromkeys(
            f"{e.label} {e.client_random} {e.secret}" for e in entries
        ))

    @staticmethod
    def _read_keylog_since(path, offset):
        """Text of *path* after byte *offset* (all of it if truncated below); bad bytes are replaced."""
        with open(path, "rb") as handle:
            size = os.fstat(handle.fileno()).st_size
            handle.seek(offset if offset <= size else 0)
            return handle.read().decode("utf-8", errors="replace")

    @staticmethod
    def _file_size(path):
        """Size of *path* in bytes, 0 if it does not exist or is unreadable."""
        try:
            return os.path.getsize(path)
        except OSError:
            return 0

    def _track_wine_proc(self, proc):
        """Register a gdb or launched-Wine process for teardown.

        Each is a session leader (start_new_session=True), so its pgid is recorded
        and killpg'd later, which works after the leader exited but the group lives.
        """
        procs = getattr(self, "_wine_procs", None)
        if procs is None:
            procs = self._wine_procs = []
        try:
            procs.append((proc, os.getpgid(proc.pid)))
        except (OSError, ProcessLookupError):
            pass

    def _terminate_wine_gdb(self):
        """Stop a running Wine GDB extraction on teardown (Ctrl-C etc.).

        The SIGINT handler force-exits right after cleanup, so this is the only
        place the gdb session (and, for spawn, the Wine tree) is stopped rather than
        orphaned. Attach mode kills only gdb's session, leaving the user's target
        running. No-op if nothing started.
        """
        import signal as _signal
        watcher = getattr(self, "_wine_watcher", None)
        if watcher is not None:
            watcher.stop()
        for _proc, pgid in getattr(self, "_wine_procs", []):
            try:
                os.killpg(pgid, _signal.SIGTERM)
            except (OSError, ProcessLookupError):
                pass
        # Watcher route, spawn: Wine may move app processes out of the launcher's
        # group, so stop the followed ones explicitly.
        if watcher is not None and self.spawn:
            for pid in watcher.alive_reported():
                try:
                    os.kill(pid, _signal.SIGTERM)
                except (OSError, ProcessLookupError):
                    pass
