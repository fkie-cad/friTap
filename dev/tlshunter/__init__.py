"""Read-only Android socket holder observations."""
from dataclasses import dataclass
import re
import shlex
import subprocess
import time


SCHEMA = "fritap.tlshunter/1"
TABLES = ("tcp", "tcp6", "udp", "udp6")


@dataclass(frozen=True)
class Config:
    device: str
    user: int
    packages: tuple[str, ...]
    seconds: float = 10
    interval: float = 1
    su: bool = False

    def __post_init__(self):
        if not self.device or self.user < 0 or not self.packages:
            raise ValueError("Specify a device, Android user and package")
        if any(not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", p)
               for p in self.packages):
            raise ValueError("Invalid Android package")
        if not (0 < self.seconds <= 300 and 0 < self.interval <= self.seconds):
            raise ValueError("Invalid observation duration or interval")


def _shell(config, command, timeout=5):
    if config.su:
        command = "su 0 sh -c " + shlex.quote(command)
    result = subprocess.run(["adb", "-s", config.device, "shell", command],
                            capture_output=True, text=True, errors="replace",
                            timeout=timeout, check=True)
    return result.stdout


def _start(stat):
    try:
        return int(stat.rsplit(")", 1)[1].split()[19])
    except (IndexError, ValueError):
        return None


def _rows(lines, table):
    for line in lines:
        fields = line.split()
        if len(fields) < 10 or not fields[9].isdigit() or fields[9] == "0":
            continue
        local, peer = fields[1:3]
        if not re.fullmatch(r"[0-9A-Fa-f]+:[0-9A-Fa-f]{4}", local) or not re.fullmatch(
                r"[0-9A-Fa-f]+:[0-9A-Fa-f]{4}", peer):
            continue
        yield fields[9], {"table": table, "local_hex": local,
                          "peer_hex": None if peer.endswith(":0000") else peer,
                          "state_hex": fields[3]}


def _snapshot(config, members, deadline):
    started = time.monotonic_ns()
    def read(command):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Sample deadline reached")
        return _shell(config, command, timeout=min(5, remaining))

    inventory = read("cat /proc/sys/kernel/random/boot_id && ps -A -o PID,UID,NAME")
    boot, _, listing = inventory.partition("\n")
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", boot):
        raise ValueError("Device boot identity unavailable")
    processes, gaps = [], []
    for line in listing.splitlines():
        parts = line.split(None, 2)
        if len(parts) != 3 or not all(p.isascii() and p.isdecimal() for p in parts[:2]):
            continue
        pid, uid = map(int, parts[:2])
        name = parts[2]
        package = name.split(":", 1)[0]
        if package not in members or members[package] != uid:
            continue
        if time.monotonic() >= deadline:
            gaps.append({"reason": "sample_deadline"})
            break
        base = f"/proc/{pid}"
        command = f"""
cat {base}/stat || exit 1
echo @identity
awk '/^Uid:/ {{print $2}}' {base}/status
tr '\\000' '\\n' < {base}/cmdline | head -n 1
echo @namespace
readlink {base}/ns/net
echo @fds
ls -l {base}/fd || echo @fd_error
for table in tcp tcp6 udp udp6; do
    echo @$table
    cat {base}/net/$table || echo TABLE_ERROR
done
echo @maps
awk '/\\.so([[:space:]]|$)/ {{print $NF}}' {base}/maps || echo MAPS_ERROR
echo @end_namespace
readlink {base}/ns/net
echo @end
cat {base}/stat || exit 1
"""
        process_started = time.monotonic_ns()
        try:
            sections = read(command).split("\n@")
        except (subprocess.SubprocessError, OSError):
            gaps.append({"pid": pid, "reason": "process_read_failed"})
            continue
        process_finished = time.monotonic_ns()
        data = dict(section.partition("\n")[::2] for section in sections[1:])
        start = _start(sections[0])
        if data.get("identity", "").splitlines() != [str(uid), name]:
            gaps.append({"pid": pid, "reason": "process_membership_unverified"})
            continue
        namespace = data.get("namespace", "").strip()
        if start is None or start != _start(data.get("end", "")):
            gaps.append({"pid": pid, "reason": "process_identity_changed"})
            continue
        if not re.fullmatch(r"net:\[\d+\]", namespace) or namespace != data.get(
                "end_namespace", "").strip():
            gaps.append({"pid": pid, "reason": "namespace_unavailable_or_changed"})
            continue
        fds = set(re.findall(r" -> socket:\[(\d+)\]$", data.get("fds", ""), re.M))
        if "fds" not in data or "fd_error" in data:
            gaps.append({"pid": pid, "reason": "fd_visibility_incomplete"})
        sockets = []
        matched = set()
        for table in TABLES:
            if table not in data or "TABLE_ERROR" in data[table]:
                gaps.append({"pid": pid, "reason": "socket_table_unavailable", "table": table})
            for inode, row in _rows(data.get(table, "").splitlines(), table):
                if inode in fds:
                    matched.add(inode)
                    sockets.append(dict(row, inode=inode))
        maps = data.get("maps", "MAPS_ERROR")
        if "MAPS_ERROR" in maps:
            gaps.append({"pid": pid, "reason": "maps_unavailable"})
        libraries = sorted({path.rsplit("/", 1)[-1] for path in maps.splitlines()
                            if re.search(r"(?:ssl|crypto|cronet|httpengine|webview|quiche|"
                                         r"nss|gnutls|fizz).*\.so$", path.rsplit("/", 1)[-1], re.I)})
        processes.append({"started_ns": process_started, "finished_ns": process_finished,
                          "library_hints": libraries, "boot_id": boot, "pid": pid, "start_ticks": start,
                          "uid": uid, "name": name, "package": package,
                          "netns": namespace, "sockets": sockets,
                          "unmatched_socket_fds": len(fds - matched)})
    foreground = None
    if time.monotonic() < deadline:
        try:
            activities = read("out=\"$(dumpsys activity activities)\" || exit 1; "
                              "printf '%s\\n' \"$out\" | "
                              "grep -E 'mResumedActivity|topResumedActivity' || true")
            foreground = sorted(set(re.findall(
                rf"\bu{config.user} ([A-Za-z0-9_.]+)/", activities)))
        except (subprocess.SubprocessError, OSError):
            gaps.append({"reason": "foreground_unavailable"})
    return {"foreground_hint": foreground, "started_ns": started, "finished_ns": time.monotonic_ns(),
            "processes": processes, "gaps": gaps}


def observe(config):
    """Yield phase markers and scope-limited observations using host monotonic time."""
    installed = _shell(config, f"cmd package list packages -U --user {config.user}")
    members = {name: int(uid) for name, uid in
               re.findall(r"^package:(\S+) uid:(\d+)\s*$", installed, re.M)
               if name in config.packages and int(uid) // 100000 == config.user}
    if len(members) != len(set(config.packages)):
        raise ValueError("Could not resolve every selected package for this Android user")
    for phase in ("baseline", "interaction"):
        yield {"schema": SCHEMA, "type": "phase", "phase": phase,
               "time_ns": time.monotonic_ns()}
        deadline = time.monotonic() + config.seconds
        while time.monotonic() < deadline:
            before = time.monotonic()
            try:
                sample = _snapshot(config, members, deadline)
            except (subprocess.SubprocessError, OSError, ValueError):
                sample = {"started_ns": int(before * 1e9), "finished_ns": time.monotonic_ns(),
                          "processes": [], "gaps": [{"reason": "inventory_failed"}]}
            yield dict(sample, schema=SCHEMA, type="sample", phase=phase)
            time.sleep(max(0, min(deadline, before + config.interval) - time.monotonic()))


def summarize(observations):
    """Return first observations per socket holder and phase."""
    first = {}
    gaps = 0
    for sample in observations:
        gaps += len(sample.get("gaps", ()))
        for process in sample.get("processes", ()):
            identity = tuple(process[k] for k in ("boot_id", "pid", "start_ticks", "netns"))
            for sock in process["sockets"]:
                key = (sample["phase"], identity, sock["table"], sock["inode"],
                       sock["local_hex"], sock["peer_hex"])
                first.setdefault(key, {"phase": sample["phase"], "process": identity,
                                       "name": process["name"], "socket": sock,
                                       "finished_ns": sample["finished_ns"]})
    baseline = {key[1:] for key in first if key[0] == "baseline"}
    for key, observation in first.items():
        if key[0] == "interaction":
            observation["seen_at_baseline"] = key[1:] in baseline
    return {"schema": SCHEMA, "type": "summary", "first_observations": list(first.values()),
            "gap_count": gaps, "action_attribution": "unresolved"}


def lead_time_bounds(candidate_host_ns, handshake_device_ns,
                     offset_min_ns, offset_max_ns):
    """Return lead-time bounds given device-minus-host clock offset bounds."""
    if offset_min_ns > offset_max_ns:
        raise ValueError("Invalid clock offset bounds")
    return (handshake_device_ns - offset_max_ns - candidate_host_ns,
            handshake_device_ns - offset_min_ns - candidate_host_ns)
