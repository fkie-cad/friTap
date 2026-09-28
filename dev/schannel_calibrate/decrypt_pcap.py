#!/usr/bin/env python3
"""Decrypt a capture with tshark, immune to the local Wireshark profile.

Two things make this more than `tshark -r ... -o tls.keylog_file:...`.

First, TLS 1.3 decrypts here even when the keylog holds *only* the application
traffic secrets. Since 4.6.0 Wireshark installs an application-data decoder even
though `CLIENT_HANDSHAKE_TRAFFIC_SECRET` is missing (gitlab commit b451b5069,
issue #20240). That works because a record failing its AEAD auth tag returns
before `decoder->seq++`, so the decoder free-runs past the handshake-epoch
records it cannot read and is still at seq 0 when real application data starts.

Second, and the reason this script exists: `tls.ignore_ssl_mac_failed: TRUE` in
a personal Wireshark profile silently destroys that. It removes the early
return, so every unreadable handshake record burns a sequence number, the nonce
is wrong from then on, and *nothing* decrypts - with no error, just an empty
result that looks like a bad keylog. So every run here is hermetic: an empty
WIRESHARK_CONFIG_DIR, and the preference pinned off explicitly.

    python3 tools/decrypt_pcap.py -i capture.pcap -k keys.keylog -- -Y http.request
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable, Sequence

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_NO_TSHARK = 3

# The missing-handshake-secret workaround landed in 4.6.0; it is absent from the
# release-4.4 and release-4.2 branches.
MIN_APP_SECRET_ONLY_VERSION = (4, 6)

# Same resolution order as friTap/offline/tshark.py:find_tshark. Duplicated on
# purpose: this script is meant to stay copy-paste portable, with no friTap import.
TSHARK_FALLBACKS = (
    "/Applications/Wireshark.app/Contents/MacOS/tshark",
    "/opt/homebrew/bin/tshark",
    "/usr/local/bin/tshark",
)

PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_DSB = 0x0000000A

_EMPTY_CONFIG_DIR: str | None = None


def _fail(message: str, code: int = EXIT_USAGE) -> "NoReturn":  # noqa: F821
    """Exit with a `[!]`-prefixed message and an explicit status code."""
    print(f"[!] {message}", file=sys.stderr)
    raise SystemExit(code)


def split_passthrough(argv: Sequence[str]) -> tuple[list[str], list[str]]:
    """Split our own flags from the ones destined for tshark.

    Done by hand rather than with argparse.REMAINDER, which only swallows the
    rest of the line once it has already consumed a positional.
    """
    argv = list(argv)
    if "--" not in argv:
        return argv, []
    cut = argv.index("--")
    return argv[:cut], argv[cut + 1:]


def find_tshark(explicit: str | None = None) -> str:
    """Locate a tshark binary, or exit 3 saying where we looked."""
    candidates: list[str] = []
    if explicit:
        candidates.append(explicit)
    for var in ("FRITAP_TSHARK", "TSHARK_PATH"):
        value = os.environ.get(var)
        if value:
            candidates.append(value)

    for candidate in candidates:
        resolved = shutil.which(candidate) or (
            candidate if os.path.isfile(candidate) and os.access(candidate, os.X_OK) else None)
        if resolved:
            return resolved
        if explicit and candidate == explicit:
            _fail(f"--tshark-path does not point at an executable: {explicit}", EXIT_NO_TSHARK)

    on_path = shutil.which("tshark")
    if on_path:
        return on_path

    for fallback in TSHARK_FALLBACKS:
        if os.path.isfile(fallback) and os.access(fallback, os.X_OK):
            return fallback

    _fail("tshark not found on PATH, in $FRITAP_TSHARK/$TSHARK_PATH, or at "
          + ", ".join(TSHARK_FALLBACKS), EXIT_NO_TSHARK)


def tshark_version(path: str) -> tuple[int, ...]:
    """Version tuple of a tshark binary, or () if it cannot be determined."""
    try:
        out = subprocess.run([path, "--version"], capture_output=True, text=True,
                             timeout=30, env=hermetic_env()).stdout
    except (OSError, subprocess.SubprocessError):
        return ()
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", out)
    return tuple(int(g) for g in match.groups()) if match else ()


def keylog_labels(paths: Iterable[Path]) -> set[str]:
    """Every NSS label appearing in the given keylogs."""
    labels: set[str] = set()
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                labels.add(line.split()[0])
    return labels


def needs_app_secret_workaround(labels: set[str]) -> bool:
    """True when the keylog has application secrets but no handshake secrets.

    That is the combination only Wireshark >= 4.6 can decrypt.
    """
    has_app = any(label.endswith("TRAFFIC_SECRET_0") for label in labels)
    has_handshake = any("HANDSHAKE_TRAFFIC_SECRET" in label for label in labels)
    return has_app and not has_handshake


def warn_if_outdated(version: tuple[int, ...], labels: set[str]) -> None:
    """Say so plainly when this tshark cannot do what the keylog requires."""
    if not version or not needs_app_secret_workaround(labels):
        return
    if version[:2] < MIN_APP_SECRET_ONLY_VERSION:
        shown = ".".join(str(part) for part in version)
        print(f"[!] this keylog has application traffic secrets but no handshake "
              f"secrets, which needs tshark >= 4.6.0; found {shown}", file=sys.stderr)


def has_embedded_secrets(path: Path) -> bool:
    """True when a pcapng carries at least one Decryption Secrets Block.

    Walks the block chain rather than scanning for the DSB type as raw bytes:
    `0a 00 00 00` turns up routinely inside packet payloads, so a byte scan
    reports false positives on plain captures.
    """
    try:
        with path.open("rb") as handle:
            header = handle.read(12)
            if len(header) < 12:
                return False
            if struct.unpack("<I", header[:4])[0] != PCAPNG_SHB:
                return False  # a classic pcap, which cannot hold secrets at all
            endian = "<" if struct.unpack("<I", header[8:12])[0] == 0x1A2B3C4D else ">"

            handle.seek(0)
            while True:
                head = handle.read(8)
                if len(head) < 8:
                    return False  # clean end of file: no DSB anywhere
                block_type, total_length = struct.unpack(endian + "II", head)
                if total_length < 12 or total_length % 4:
                    return False  # malformed; refuse to guess
                if block_type == PCAPNG_DSB:
                    return True
                handle.seek(total_length - 8, os.SEEK_CUR)
    except OSError:
        return False


def merge_keylogs(paths: Sequence[Path]) -> Path:
    """One keylog path for tshark, which accepts only a single file.

    A single input is passed straight through. Several are concatenated with
    duplicate lines dropped, keeping first-seen order so the result stays
    diffable against its inputs.
    """
    for path in paths:
        if not path.is_file():
            _fail(f"keylog not found: {path}")
    if len(paths) == 1:
        return paths[0]

    seen: set[str] = set()
    merged: list[str] = []
    for path in paths:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip() and line not in seen:
                seen.add(line)
                merged.append(line)

    handle = tempfile.NamedTemporaryFile(
        mode="w", suffix=".keylog", prefix="decrypt_pcap_", delete=False, encoding="utf-8")
    with handle:
        handle.write("\n".join(merged) + "\n")
    return Path(handle.name)


def hermetic_env() -> dict[str, str]:
    """Environment pointing Wireshark at empty, throwaway config and home dirs.

    Without this the personal profile is read, and it can carry an ambient
    `tls.keylog_file`, an RSA key list, or the `tls.ignore_ssl_mac_failed: TRUE`
    that breaks TLS 1.3 decryption outright.

    HOME is redirected too, because the personal *plugin* directory
    (`~/.local/lib/wireshark/plugins`) hangs off HOME and not off
    WIRESHARK_CONFIG_DIR. A stray Lua dissector there changes how packets are
    dissected, so leaving it loaded would undercut the point of this script.
    """
    global _EMPTY_CONFIG_DIR
    if _EMPTY_CONFIG_DIR is None:
        _EMPTY_CONFIG_DIR = tempfile.mkdtemp(prefix="decrypt_pcap_wsconf_")
    return {**os.environ,
            "WIRESHARK_CONFIG_DIR": _EMPTY_CONFIG_DIR,
            "HOME": _EMPTY_CONFIG_DIR}


def build_command(tshark: str, pcap: Path, keylog: Path | None,
                  passthrough: Sequence[str] = (), check: bool = False) -> list[str]:
    """Assemble the tshark argv."""
    cmd = [tshark, "-r", str(Path(pcap).resolve())]
    if keylog is not None:
        cmd += ["-o", f"tls.keylog_file:{Path(keylog).resolve()}"]
    # Redundant given the hermetic config dir, but this is the line a future
    # reader will grep for, so it states the requirement where it is visible.
    cmd += ["-o", "tls.ignore_ssl_mac_failed:FALSE"]
    if check:
        cmd += ["-q", "-z", "io,phs"]
    cmd += list(passthrough)
    return cmd


def decrypted_children(hierarchy: str, parent: str = "tls") -> list[tuple[str, int]]:
    """Protocols nested under `parent` in `-z io,phs` output, largest first.

    Anything below `tls` other than `tls` itself only appears once a record has
    actually been decrypted, which makes this a direct read on whether the keys
    worked.

    Names repeat in the hierarchy - phs nests `http2` inside `http2` for a
    tunnelled stream - so each name is reported once, with the frame count of
    its shallowest occurrence rather than a sum that would count frames twice.
    """
    totals: dict[str, int] = {}
    parent_indent: int | None = None
    for line in hierarchy.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("="):
            continue
        indent = len(line) - len(line.lstrip())
        name = stripped.split()[0]
        if parent_indent is not None and indent <= parent_indent:
            parent_indent = None  # left the subtree
        if name == parent and parent_indent is None:
            parent_indent = indent
            continue
        if parent_indent is not None and name != parent:
            match = re.search(r"frames:(\d+)", stripped)
            frames = int(match.group(1)) if match else 0
            totals[name] = max(totals.get(name, 0), frames)
    return sorted(totals.items(), key=lambda item: (-item[1], item[0]))


def run_check(cmd: Sequence[str]) -> int:
    """Run the hierarchy pass and report whether anything decrypted."""
    proc = subprocess.run(cmd, capture_output=True, text=True, env=hermetic_env())
    sys.stdout.write(proc.stdout)
    if proc.stderr:
        sys.stderr.write(proc.stderr)
    if proc.returncode != 0:
        return proc.returncode

    children = decrypted_children(proc.stdout)
    if children:
        summary = ", ".join(f"{name} ({frames} frames)" for name, frames in children)
        print(f"[+] decrypted payload under tls: {summary}")
    else:
        print("[!] nothing decrypted under tls - the keys do not match this capture, "
              "or no TLS application data was captured")
    return EXIT_OK


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="decrypt_pcap.py", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-i", "--input", required=True, type=Path, metavar="PCAP",
                        help="capture to decrypt (.pcap or .pcapng)")
    parser.add_argument("-k", "--keylog", action="append", type=Path, default=None,
                        metavar="KEYLOG",
                        help="NSS keylog; repeatable, several are merged. Optional when "
                             "the input is a pcapng carrying embedded secrets (DSB).")
    parser.add_argument("--tshark-path", default=None,
                        help="tshark binary to use instead of the autodetected one")
    parser.add_argument("-n", "--print-command", action="store_true",
                        help="print the tshark command and exit without running it")
    parser.add_argument("--check", action="store_true",
                        help="report which protocols decrypted, instead of dissecting packets")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    own, passthrough = split_passthrough(sys.argv[1:] if argv is None else argv)
    args = parse_args(own)

    if not args.input.is_file():
        _fail(f"capture not found: {args.input}")

    keylogs = list(args.keylog or [])
    if keylogs:
        keylog = merge_keylogs(keylogs)
    elif has_embedded_secrets(args.input):
        keylog = None
        print(f"[*] no -k given; using the secrets embedded in {args.input.name}")
    else:
        _fail(f"no -k given and {args.input.name} has no embedded decryption secrets")

    tshark = find_tshark(args.tshark_path)
    cmd = build_command(tshark, args.input, keylog, passthrough, check=args.check)

    if args.print_command:
        print(f"WIRESHARK_CONFIG_DIR={hermetic_env()['WIRESHARK_CONFIG_DIR']} "
              + " ".join(cmd))
        return EXIT_OK

    warn_if_outdated(tshark_version(tshark), keylog_labels(keylogs))

    if args.check:
        return run_check(cmd)
    return subprocess.run(cmd, env=hermetic_env()).returncode


if __name__ == "__main__":
    raise SystemExit(main())
