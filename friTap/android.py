#!/usr/bin/env python3

import logging
import os
import re
import shlex
import subprocess
import time
from enum import Enum
from functools import cached_property, wraps
from os.path import exists as file_exists

from .backends import BackendInvalidArgumentError, get_backend
from .constants import build_capture_bpf
from .fritap_utility import Failure


class RootState(Enum):
    """Outcome of the device root check. UNKNOWN means the probe timed out."""
    ROOTED = "rooted"
    NOT_ROOTED = "not rooted"
    UNKNOWN = "unknown"


class Android:
    tcpdump_arch_map = {
        "arm64": "tcpdump_arm64_android",
        "arm": "tcpdump_arm32_android",
        "ia32": "tcpdump_x86_android",
        "x64": "tcpdump_x86_64_android",
    }
    dst_path = "/data/local/tmp/"
    pcap_name = ""
    # Device pid of the tcpdump friTap started (read from its pidfile).
    tcpdump_pid = None

    def __init__(self,  device_id=None):
        self.device_id = device_id
        self.logger = logging.getLogger('friTap')
        self._backend = get_backend()

    @cached_property
    def adb(self):
        return ADB.find(device_id=self.device_id)

    @cached_property
    def device(self):
        return self.get_frida_device()

    @cached_property
    def tcpdump_version(self):
        arch = self._get_android_device_arch()
        try:
            return self.tcpdump_arch_map[arch]
        except KeyError:
            self.logger.error("unknown arch.")
            self.logger.error("We can't find your device architecture, please set mobile arch via --m_arch <arm64|arm|ia32|x64>")
            self.logger.error("Leaving....")
            raise Failure

    def get_frida_device(self):
        try:
            if self.device_id:
                return self._backend.get_device(mobile=self.device_id)
            return self._backend.get_device(mobile=True)
        except BackendInvalidArgumentError:
            self.logger.error(f"Device not found. Please verify the device ID: {self.device_id}")
            raise Failure

    def adb_check_root(self):
        return self.adb.is_rooted

    @property
    def root_state(self):
        """Tri-state root check result (see :class:`RootState`)."""
        return self.adb.root_state or (
            RootState.ROOTED if self.adb.is_rooted else RootState.NOT_ROOTED)

    def _adb_push_file(self, src_file,dst):
        return self.adb.run('push', src_file, dst, timeout=30)
    push_file = _adb_push_file
    
    def _adb_pull_file(self,src_file,dst):
        return self.adb.run('pull', src_file, dst, timeout=30)
    pull_file = _adb_pull_file

    def file_exists(self, path):
        result = self.adb.shell('stat', f'"{path}"')
        return result.returncode == 0

    def _get_android_device_arch(self):
        try:
            system_params = self._backend.query_system_parameters(self.device)
        except Exception:
            # Defaulting to ARM64
            return "arm64"
        return system_params.get('arch', 'arm64')
    
    
    def _adb_make_binary_executable(self, path):
        self.adb.shell(f'chmod +x "{path}{self.tcpdump_version}"')

    def assure_android(func):
        wraps(func)
        def wrapped(self, *args, **kwargs):
            if not self.is_Android:
                raise Failure(info="[-] none Android device\nclosing friTap...")
            return func(self, *args, **kwargs)
        return wrapped

    @property
    def tcpdump_path(self):
        if self.is_tcpdump_available:
            return "tcpdump"
        return f"{self.dst_path}./{self.tcpdump_version}"

    @property
    def tcpdump_cmd(self):
        return "tcpdump" if self.is_tcpdump_available else self.tcpdump_version
        
    @cached_property
    def is_tcpdump_available(self):
        try:
            # Check if tcpdump is available on the device
            result = self.adb.shell("tcpdump --version")
            return result.returncode == 0
        except Exception as e:
            self.logger.warning(f"Error checking tcpdump availability: {e}")
            return False
            
    
    def _get_tcpdump_version(self):
        # Get the path to the current file
        current_dir = os.path.dirname(__file__)

        # Construct the path to the assets directory
        tcpdump_path = os.path.join(current_dir, 'assets', 'tcpdump_binaries', self.tcpdump_version)

        if file_exists(tcpdump_path):
            self.logger.info(f"installing tcpdump to Android device: {tcpdump_path}")
            return tcpdump_path
        else:
            self.logger.error(f"can't find {tcpdump_path}")
            self.logger.error(f"ensure that {tcpdump_path} exists")
            raise Failure

    @assure_android
    def install_tcpdump(self):
        tcpdump_path = self._get_tcpdump_version()
        return_Value = self._adb_push_file(tcpdump_path,self.dst_path)

        if return_Value.returncode != 0:
            self.logger.error(f"error: {return_Value.stderr}")
            self.logger.error("it might help to adjust the dst_path or to ensure that you have adb in your path")
            raise Failure

        self._adb_make_binary_executable(self.dst_path)
        self.logger.info(f"pushed tcpdump to {self.dst_path} on your android device")
        return True
            
    @assure_android
    def pull_pcap_from_device(self, dest_dir=".", local_path=None):
        """Pull the on-device tcpdump capture to ``dest_dir``.

        ``dest_dir`` must be the directory that holds the host-side output pcap,
        because the finalize step (PCAP._temp_pcap_path) reads the pulled file
        from ``<output_dir>/_<output_basename>``. Defaulting to "." only works
        when the output pcap lives in the current working directory; callers
        with an output path elsewhere (e.g. an absolute path) must pass the
        output directory or the pulled capture is silently dropped.

        ``local_path`` names the pulled file explicitly; it is needed when the
        device file carries a per-run unique name that differs from the local
        temp capture name.

        Returns the local path of the pulled file, or ``None`` if the pull failed.
        """
        pcap_path = self.dst_path + self.pcap_name
        target = local_path or os.path.join(dest_dir or ".", self.pcap_name)
        return_Value = self._adb_pull_file(pcap_path, target)
        # adb reports the pull summary on stderr (stdout stays empty).
        summary = (return_Value.stdout or return_Value.stderr or "").strip()
        self.logger.info(f"pulling capture from device: {summary}")
        self.logger.debug("---------------------------------\n%s", return_Value)
        if return_Value.returncode !=0:
            self.logger.error(f"error pulling pcap ({pcap_path}) from android device")
            return None
        return target

    def _capture_pidfile(self):
        """Device path of the pidfile next to the tcpdump temp capture."""
        return f"{self.dst_path}{self.pcap_name}.pid"

    def remove_device_capture(self):
        """Delete the on-device tcpdump temp file and its pidfile (best effort, never raises)."""
        if not self.pcap_name:
            return
        try:
            self.adb.shell(
                f'rm -f "{self.dst_path}{self.pcap_name}" "{self._capture_pidfile()}"',
                timeout=10)
        except Exception as exc:
            self.logger.debug("could not remove %s%s from the device: %s",
                              self.dst_path, self.pcap_name, exc)

    # Teardown adb calls run while the device may still be busy (the target,
    # frida-server and tcpdump all compete for the CPU), so they get a generous
    # timeout and several attempts instead of the 5-10 s used elsewhere.
    TEARDOWN_ADB_TIMEOUT = 20
    TEARDOWN_STOP_ATTEMPTS = 3

    def stop_tcpdump_gracefully(self, capture_process, grace_seconds=1.0):
        """Stop the device tcpdump so it flushes its pcap, then reap the adb client.

        Killing the local ``adb shell`` client does NOT stop the remote
        tcpdump, so it is signalled by pid: SIGINT first (tcpdump writes out its
        buffer and exits), SIGKILL on later attempts. Only the tcpdump friTap
        started (pid from its pidfile) is signalled, so a concurrent capture of
        another friTap run survives; every tcpdump is stopped only when that
        pid is unknown. A lookup that times out is retried rather than read as
        "already stopped". Never raises.
        """
        list_pids = self._capture_pid_lister()
        signal_name = "INT"
        for _attempt in range(self.TEARDOWN_STOP_ATTEMPTS):
            pids = list_pids()
            if pids == []:
                break
            if pids:
                self._signal_pids(pids, signal_name)
                signal_name = "KILL"  # it had its chance to flush
                time.sleep(grace_seconds)
        else:
            if list_pids() != []:
                self.logger.warning(
                    "tcpdump may still be running on the device; stop it with: "
                    "adb shell su 0 kill %s",
                    self.tcpdump_pid if self.tcpdump_pid is not None else "$(pidof tcpdump)")
        self._reap_local_process(capture_process)

    def _capture_pid_lister(self):
        """Callable returning the pids to stop: friTap's own tcpdump, else all of them."""
        pid = self._recorded_tcpdump_pid()
        if pid is not None:
            return lambda: self._recorded_pid_state(pid)
        self.logger.warning(
            "pid of friTap's device tcpdump is unknown; stopping every tcpdump "
            "process on the device")
        return self._tcpdump_pids_or_none

    def _recorded_tcpdump_pid(self):
        """Pid written to the capture pidfile at launch, or ``None`` if unavailable."""
        if self.tcpdump_pid is None and self.pcap_name:
            try:
                out = self.adb.shell(f'cat "{self._capture_pidfile()}"',
                                     timeout=self.TEARDOWN_ADB_TIMEOUT).stdout or ""
            except Exception as exc:
                self.logger.debug("could not read the tcpdump pidfile: %s", exc)
                return None
            out = out.strip()
            self.tcpdump_pid = int(out) if out.isdigit() else None
        return self.tcpdump_pid

    def _recorded_pid_state(self, pid):
        """``[pid]`` while it is still a tcpdump, ``[]`` once gone, ``None`` if unknown."""
        try:
            result = self.adb.shell(f"cat /proc/{int(pid)}/comm",
                                    timeout=self.TEARDOWN_ADB_TIMEOUT)
        except Exception as exc:
            self.logger.debug("could not check tcpdump pid %s: %s", pid, exc)
            return None
        # A recycled pid running something else counts as gone.
        return [pid] if "tcpdump" in (result.stdout or "") else []

    def _tcpdump_pids_or_none(self):
        """Pids of the device tcpdump, ``[]`` if none, ``None`` if unknown (timeout)."""
        try:
            return self.get_pids(self.tcpdump_cmd, timeout=self.TEARDOWN_ADB_TIMEOUT)
        except Exception as exc:
            self.logger.debug("could not list tcpdump processes: %s", exc)
            return None

    def _signal_pids(self, pids, signal_name):
        pids_str = " ".join(map(str, pids))
        try:
            self.adb.shell(f"kill -{signal_name} {pids_str}", timeout=self.TEARDOWN_ADB_TIMEOUT)
            self.logger.debug("Sent SIG%s to tcpdump PID(s): %s", signal_name, pids_str)
        except Exception as exc:
            self.logger.debug("kill -%s %s failed: %s", signal_name, pids_str, exc)

    def _reap_local_process(self, process, timeout=5):
        if process is None or process == -1:
            return
        try:
            process.terminate()
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
        except Exception as exc:
            self.logger.debug("Exception while reaping the adb tcpdump client: %s", exc)

    def get_pid(self, process_name):
        pids = self.get_pids(process_name)
        if pids:
            return pids[0]

    def get_pids(self, process_name, timeout=10):
        try:
            pid_result =self.adb.shell(f'pidof -x "{process_name}"', timeout=timeout).stdout
            pids = pid_result.strip().split()

            if not pids:
                self.logger.debug("No PID found. Process may not be running.")
            return [int(pid) for pid in pids]
        except subprocess.CalledProcessError as e:
            self.logger.exception("Running error: %s", e.stderr.strip())
        except ValueError:
            self.logger.exception("got non-numeric pids?")
        return []

    @assure_android
    def _run_for_pids(self, cmd_on_pids):
        pids = self.get_pids(self.tcpdump_cmd)
        if pids:
            pids_str = " ".join(map(str, pids))
            self.adb.shell(cmd_on_pids % pids_str)
            self.logger.debug("Killed processes with PID: %s", pids_str)
        else:
            self.logger.debug("No running tcpdump processes found")
        
    def start_application(self, package_name, activity=None):
        """Start an Android application using the instrumentation backend.

        When *activity* is given, the app is spawned directly onto that activity
        via Frida's ``activity`` spawn option, so hooks are in place before any
        app code runs (pass a relative ``.SomeActivity`` or a fully-qualified
        class name). Without it, the default launcher activity is spawned.
        """
        aux = {"activity": activity} if activity else None
        pid = self._backend.spawn_raw(self.device, package_name, aux=aux)
        self._backend.resume(self.device, pid)
        return True

    def detect_ssl_libraries(self, package_name):
        """Detect SSL/TLS libraries available for an Android application."""
        result = self.adb.shell(
            f'find /system/lib* /data/app/{package_name}/ -name "*.so" 2>/dev/null',
            timeout=15,
        )
        ssl_patterns = ['ssl', 'crypto', 'boringssl', 'conscrypt', 'nss', 'gnutls', 'wolfssl', 'mbedtls']
        all_libs = result.stdout.strip().splitlines()
        return [lib for lib in all_libs if any(p in lib.lower() for p in ssl_patterns)]

    def get_library_path(self, package_name, library_name):
        """Get the path of a specific library in an Android application."""
        result = self.adb.shell(
            f'find /system/lib* /data/app/{package_name}/ -name "{library_name}" 2>/dev/null',
            timeout=15,
        )
        lines = result.stdout.strip().splitlines()
        return lines[0] if lines else None

    def check_library_exports(self, library_path):
        """Check exports of a library on the Android device."""
        result = self.adb.run('shell', 'nm', '-D', library_path, timeout=15)
        return result.stdout.strip().splitlines()

    # ------------------------------------------------------------------
    # Crash diagnostics — post-mortem forensics for a crashed target.
    # These own the device-side shell knowledge (log buffers, tombstone
    # layout) so callers only handle presentation/parsing. They run on an
    # already-dead process as best-effort forensics and therefore never raise;
    # they return empty results when the artifact is unavailable (no root,
    # nothing found, adb error). Most devices require root for both.
    # ------------------------------------------------------------------
    def get_crash_logcat(self, timeout=20):
        """Return the device ``crash`` logcat buffer (``logcat -b crash -d``).

        This buffer holds the ART ``Fatal signal`` / ``Abort message`` lines
        almost immediately after a crash (no tombstone-write race). Returns
        ``""`` when unavailable.
        """
        try:
            return self.adb.shell("logcat -b crash -d", timeout=timeout).stdout or ""
        except Exception:
            self.logger.debug("get_crash_logcat failed", exc_info=True)
            return ""

    _DEVICE_CLOCK_RE = re.compile(r"^\s*(\d+)([+-])(\d{2})(\d{2})\s*$")

    def get_device_clock(self, timeout=10):
        """Return ``(epoch_seconds, utc_offset_seconds)`` of the device clock, or
        ``None`` when it cannot be read.

        Device logcat/tombstone timestamps are wall-clock times in the DEVICE's
        timezone, which need not match the host's; this is what maps them onto
        an absolute timeline. ``date +%s%z`` (one token, so no shell quoting
        through the root elevator) prints e.g. ``1730000000+0100``.
        """
        try:
            out = self.adb.shell("date +%s%z", timeout=timeout).stdout or ""
        except Exception:
            self.logger.debug("get_device_clock failed", exc_info=True)
            return None
        m = self._DEVICE_CLOCK_RE.match(out.strip().splitlines()[-1] if out.strip() else "")
        if not m:
            return None
        sign = -1 if m.group(2) == "-" else 1
        offset = sign * (int(m.group(3)) * 3600 + int(m.group(4)) * 60)
        return int(m.group(1)), offset

    def get_latest_tombstone(self, pid=None, cmdline_hint="", list_timeout=15, cat_timeout=30):
        """Return ``(path, text)`` of the newest ``/data/tombstones`` entry that
        belongs to the crashed process, or ``(None, "")``.

        Guards against attaching an unrelated app's tombstone by requiring the
        given *pid* or *cmdline_hint* to appear in the dump (a non-match yields
        ``(None, "")``). Returns ``(None, "")`` when unavailable.
        """
        try:
            listing = self.adb.shell(
                "ls -t /data/tombstones/tombstone_*", timeout=list_timeout).stdout or ""
            newest = listing.splitlines()[0].strip() if listing.strip() else None
            if not newest:
                return None, ""
            text = self.adb.shell(f"cat {newest}", timeout=cat_timeout).stdout or ""
            matches = (not pid or str(pid) in text) and (not cmdline_hint or cmdline_hint in text)
            if text.strip() and matches:
                return newest, text
            return None, ""
        except Exception:
            self.logger.debug("get_latest_tombstone failed", exc_info=True)
            return None, ""

    def send_ctrlC_over_adb(self):
        return self._run_for_pids("kill -INT %s")

    def send_kill_tcpdump_over_adb(self): 
        return self._run_for_pids("kill -9 %s")


    @assure_android
    def run_tcpdump_capture(self, pcap_name, include_loopback=False, filter_infrastructure=True):
        """Start tcpdump on the device writing ``dst_path + pcap_name``.

        The command runs as ``sh -c 'echo $$ > <pidfile>; exec tcpdump ...'``:
        ``exec`` keeps the shell's pid, so the pidfile holds tcpdump's own pid
        and the teardown can stop exactly this capture.
        """
        self.pcap_name = pcap_name
        self.tcpdump_pid = None
        bpf = build_capture_bpf(filter_infrastructure=filter_infrastructure,
                                include_loopback=include_loopback)
        tcpdump_cmd = f'{self.tcpdump_path} -U -i any -s 0 -w {self.dst_path}{pcap_name}'
        if bpf:
            tcpdump_cmd += f' "{bpf}"'
        return self.adb.shell(self._with_pidfile(tcpdump_cmd), background=True)

    def _with_pidfile(self, cmd):
        """Wrap *cmd* so the device writes its pid to the capture pidfile first."""
        script = f'echo $$ > "{self._capture_pidfile()}"; exec {cmd}'
        return f"sh -c {shlex.quote(script)}"

    def start_tcpdump(self, pcap_name):
        return self.run_tcpdump_capture(pcap_name)

    def stop_tcpdump(self, capture_process):
        if capture_process:
            try:
                capture_process.terminate()
                capture_process.wait(timeout=2)
            except Exception as exc:
                self.logger.debug("Exception while closing tcpdump: %s", exc)
                return False
        else:
            self.send_kill_tcpdump_over_adb()
        return True
            

    def check_adb_availability(self):
        try:
            subprocess.run(['adb', 'version'], capture_output=True, text=True, timeout=5)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self.logger.error("can't find adb in your path. Please ensure that adb is installed and in your path if you are trying a full capture on Android.")
            return False

    def list_devices(self):
        lines = subprocess.run(['adb', 'devices'], capture_output=True, text=True, timeout=10).stdout.splitlines()
        return [x.split()[0] for x in lines[1:] if x]

    def list_installed_packages(self):
        lines = self.adb.shell('pm', 'list', 'packages', timeout=15).stdout.splitlines()
        return [self.adb._parse_package_name(x) for x in lines]

    @cached_property
    def is_Android(self):
        if self.check_adb_availability() and self.list_devices():
            return True
        self.logger.error("No device connected to adb. Ensure that adb devices will print your device if you are trying a full capture on Android.")
        return False
        
class ADB:
    def __init__(self, device_id=None):
        self.device_id = device_id
        self.logger = logging.getLogger('friTap')

    def _to_runlist(self, *args):
        if len(args) == 1:
            return shlex.split(args[0]) if isinstance(args[0], str) else args[0]
        return args

    def logger_debug(self, msg, *args):
        """
        Logging helper that stringifys the args but only if logging is DEBUG.
        This is to not unnecessarily build lists in non-debug cases.
        """
        from .fritap_utility import stringify_list
        if self.logger.level <= logging.DEBUG:
            args_list = stringify_list(args)
            self.logger.debug(msg, args_list)

    # Root probing. `su 0 id -u` routinely takes >1 s while Frida is attaching
    # (frida-server, adbd and su all compete for the CPU), so the probe gets a
    # realistic timeout plus one retry, and a probe that never answers yields
    # RootState.UNKNOWN instead of being mistaken for "not rooted".
    ROOT_PROBE_TIMEOUT = 5
    ROOT_PROBE_ATTEMPTS = 2
    # Elevators that run commands through `su` (see _resolve_unknown_root).
    uses_su = False
    # Set by find(); a directly constructed ADB is a plain, verified-unrooted one.
    root_state = None

    @property
    def is_rooted(self):
        return type(self) is not ADB

    def probe_uid(self, timeout=None, attempts=None):
        """Return the uid `id -u` reports through this elevator.

        Returns ``None`` when every attempt timed out (state unknown). Raises
        ``ValueError`` when the command answered but not with a uid, e.g. a
        missing `su` binary or an `su` that rejects this elevator's syntax.
        """
        timeout = timeout or self.ROOT_PROBE_TIMEOUT
        attempts = attempts or self.ROOT_PROBE_ATTEMPTS
        for attempt in range(1, attempts + 1):
            try:
                result = self.shell('id -u', timeout=timeout)
            except subprocess.TimeoutExpired:
                self.logger.debug("%s: `id -u` timed out after %ss (attempt %d/%d)",
                                  type(self).__name__, timeout, attempt, attempts)
                continue
            return int(result.stdout)
        return None

    @classmethod
    def probe_root(cls, device_id=None):
        """Classify this elevator as ROOTED, NOT_ROOTED or UNKNOWN (timed out)."""
        try:
            uid = cls(device_id=device_id).probe_uid()
        except ValueError:
            return RootState.NOT_ROOTED
        if uid is None:
            return RootState.UNKNOWN
        return RootState.ROOTED if uid == 0 else RootState.NOT_ROOTED

    def su_available(self):
        """True when an `su` binary is on the device's PATH (never raises)."""
        try:
            result = self.shell('command -v su', timeout=self.ROOT_PROBE_TIMEOUT)
        except (subprocess.TimeoutExpired, OSError):
            return False
        return result.returncode == 0 and bool((result.stdout or "").strip())

    def _elevator(self, cmd):
        # Base (non-rooted) ADB: run the command as the plain shell user.
        # Do NOT raise here. Raising makes the non-rooted candidate unreachable in
        # ADB.find()/detect() — every candidate then fails and find() reports a
        # misleading "[-] No ADB ..." even though plain `adb` works fine. Root is
        # enforced where it actually matters (full_mobile_capture gates on
        # adb_check_root() before attempting tcpdump).
        return cmd

    @property
    def _adb_base(self):
        if self.device_id:
            return ['adb', '-s', self.device_id]
        return ['adb']
        
    def _adb_cmd(self, *args):
        if len(args) == 1 and isinstance(args[0], str):
            return self._adb_base + shlex.split(args[0])
        return self._adb_base + list(args)

    def _parse_package_name(self, name):
        return name.split(":")[1] if ":" in name else name

    package_re = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$")
    def _validate_package_name(self, name):
        """
        https://developer.android.com/build/configure-app-module#set-application-id

        Although the application ID looks like a traditional Kotlin or Java
        package name, the naming rules for the application ID are a bit more
        restrictive:

        - It must have at least two segments (one or more dots).
        - Each segment must start with a letter.
        - All characters must be alphanumeric or an underscore [a-zA-Z0-9_].

        """
        # stringifying name makes None to 'None' which is equally invalid thus works
        return bool(self.package_re.match(str(name)))

    def run(self, *args, **kwargs):
        run_kwargs = {"capture_output": True, "text": True, "timeout": 5}
        run_kwargs.update(kwargs)       
        return self._run(self._adb_cmd(*args), **run_kwargs)

    def _run(self, *args, **kwargs):
        self.logger_debug('Running `%s`', args)
        return subprocess.run(*args, **kwargs)

    def Popen(self, *args, **kwargs):
        popen_kwargs = {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE}
        popen_kwargs.update(kwargs)
        return self._Popen(self._adb_cmd(*args), **popen_kwargs)

    def _Popen(self, *args, **kwargs):
        self.logger_debug('Running (popen/background) `%s`', args)
        return subprocess.Popen(*args, **kwargs)

    def shell(self, *args, background=False, **kwargs):
        cmd = ' '.join(args) if len(args) > 1 else args[0]
        elevated_cmd = self._elevator(cmd)
        shell_args = ['shell', elevated_cmd]
        if background:
            return self.Popen(*shell_args, **kwargs)
        else:
            return self.run(*shell_args, **kwargs)

    @staticmethod
    def find(device_id=None):
        """Return the best ADB transport for the device, tagged with its root state.

        Each root elevator is probed in turn; the first that yields uid 0 wins.
        A probe that keeps timing out is never read as "not rooted": if no
        elevator answered with root but at least one timed out, the decision is
        handed to :meth:`_resolve_unknown_root`.
        """
        timed_out = []
        for candidate in ADB.__subclasses__():
            state = candidate.probe_root(device_id=device_id)
            if state is RootState.ROOTED:
                return candidate._tagged(device_id, RootState.ROOTED)
            if state is RootState.UNKNOWN:
                timed_out.append(candidate)
        if timed_out:
            return ADB._resolve_unknown_root(device_id, timed_out)
        return ADB._verified_plain_adb(device_id)

    @classmethod
    def _tagged(cls, device_id, root_state):
        adb = cls(device_id=device_id)
        adb.root_state = root_state
        return adb

    @staticmethod
    def _verified_plain_adb(device_id):
        """The plain transport, after checking that `adb shell` answers at all."""
        try:
            uid = ADB(device_id=device_id).probe_uid()
        except (ValueError, OSError):
            uid = None
        if uid is None:
            raise Failure("[-] No ADB: there seems to be no adb and/or connection available")
        if uid == 0:  # the earlier plain probe only timed out; adbd runs as root
            return RootADB._tagged(device_id, RootState.ROOTED)
        return ADB._tagged(device_id, RootState.NOT_ROOTED)

    @staticmethod
    def _resolve_unknown_root(device_id, timed_out):
        """Pick a transport when the root probe timed out (device under load).

        With `su` present, assume root and use the su elevator that timed out:
        a busy device is far more likely than an `su` that hangs forever, and
        concluding "unrooted" would silently drop the full capture. Without
        `su`, fall back to the plain transport with an explicit explanation.
        """
        su_elevators = [candidate for candidate in timed_out if candidate.uses_su]
        if not su_elevators:
            # Every su variant answered "no root"; only the plain probe was slow.
            return ADB._verified_plain_adb(device_id)
        plain = ADB._tagged(device_id, RootState.UNKNOWN)
        if plain.su_available():
            plain.logger.warning(
                "Root check timed out twice (`su` did not answer within %ss; the "
                "device is probably busy). `su` is present, so friTap assumes root "
                "and continues with the su-based path.", ADB.ROOT_PROBE_TIMEOUT)
            return su_elevators[0]._tagged(device_id, RootState.UNKNOWN)
        plain.logger.warning(
            "Could not determine whether the device is rooted: the root check "
            "timed out and no `su` binary was found. Root-only features such as "
            "full packet capture (-f) are unavailable; run `adb root` or retry "
            "when the device is less busy.")
        return plain

    @classmethod
    def detect(cls, device_id=None):
        adb = cls(device_id=device_id)
        uid = adb.probe_uid()  # ValueError on a non-numeric answer, that's ok
        if uid is None:
            raise subprocess.TimeoutExpired(adb._adb_cmd('shell', 'id -u'),
                                            adb.ROOT_PROBE_TIMEOUT)
        if (uid == 0) == adb.is_rooted:
            return adb
        raise ValueError

class RootADB(ADB):
    # The Root elevator means: no su; works directly on uid-0 shell
    def _elevator(self, cmd):
        return cmd

class SuADB(ADB):
    uses_su = True

    def _elevator(self, cmd):
        return f'su 0 {cmd}'

class MagiskADB(ADB):
    uses_su = True

    def _elevator(self, cmd):
        # Return single string: 'su -c '<cmd>''
        # The command must be quoted for su -c to handle it as a single argument
        # Using single quotes; if cmd contains single quotes, they need escaping
        escaped_cmd = cmd.replace("'", "'\\''")  # Escape single quotes: ' -> '\''
        return f"su -c '{escaped_cmd}'"
