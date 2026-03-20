"""Install friTap backend integrations (e.g. Wireshark extcap plugin)."""

import logging
import os
import platform
import shutil
import stat
import subprocess
import sys

logger = logging.getLogger("friTap.commands")


def _find_extcap_dir() -> str | None:
    """Detect the Wireshark extcap directory."""
    # 1. Try `wireshark -G folders` for the authoritative path
    for ws_bin in ("wireshark", "Wireshark"):
        try:
            result = subprocess.run(
                [ws_bin, "-G", "folders"],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines():
                if "extcap" in line.lower():
                    # Lines look like: "Personal extcap path:  /path/to/extcap"
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        candidate = parts[1].strip()
                        if candidate:
                            return candidate
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    # 2. Platform-specific fallbacks
    system = platform.system()
    if system == "Darwin":
        candidates = [
            os.path.expanduser("~/.local/lib/wireshark/extcap"),
            "/Applications/Wireshark.app/Contents/MacOS/extcap",
        ]
    elif system == "Linux":
        candidates = [
            os.path.expanduser("~/.local/lib/wireshark/extcap"),
            "/usr/lib/x86_64-linux-gnu/wireshark/extcap",
            "/usr/lib/wireshark/extcap",
        ]
    elif system == "Windows":
        appdata = os.environ.get("APPDATA", "")
        candidates = [os.path.join(appdata, "Wireshark", "extcap")] if appdata else []
    else:
        candidates = []

    for path in candidates:
        if os.path.isdir(path):
            return path

    # Return the first user-local candidate even if it doesn't exist yet (we'll mkdir)
    if candidates:
        return candidates[0]
    return None


def _find_extcap_source() -> str | None:
    """Locate the fritap-extcap script bundled with the package."""
    here = os.path.dirname(os.path.abspath(__file__))
    # friTap/commands/ -> friTap/ -> project root
    project_root = os.path.dirname(os.path.dirname(here))
    candidate = os.path.join(project_root, "integrations", "wireshark", "fritap-extcap")
    if os.path.isfile(candidate):
        return candidate
    return None


def install_wireshark_extcap() -> None:
    """Install the friTap extcap plugin into Wireshark's extcap directory."""
    extcap_dir = _find_extcap_dir()
    if not extcap_dir:
        logger.error("Could not detect Wireshark extcap directory.")
        logger.error("Please install Wireshark first, or specify the extcap path manually.")
        sys.exit(1)

    source = _find_extcap_source()
    if not source:
        logger.error("Could not find the fritap-extcap plugin script.")
        logger.error("Please ensure friTap is properly installed.")
        sys.exit(1)

    # Create extcap directory if needed
    os.makedirs(extcap_dir, exist_ok=True)

    dest = os.path.join(extcap_dir, "fritap-extcap")
    shutil.copy2(source, dest)

    # Make executable on Unix
    if os.name != "nt":
        st = os.stat(dest)
        os.chmod(dest, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    print(f"Installed friTap extcap plugin to: {dest}")
    print("Restart Wireshark to see 'friTap TLS/SSL Capture' in the interface list.")
