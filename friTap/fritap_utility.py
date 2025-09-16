#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pathlib import Path
import frida
import platform
import os
import logging

def find_pid_by_name(proc_name: str) -> int | None:
    """
    Locate the PID of an *already-running* process whose executable name
    matches `proc_name` (case-insensitive).
    
    Parameters
    ----------
    proc_name : str
        e.g. "notepad.exe"  (".exe" optional)

    Returns
    -------
    int | None
        PID of the first match, or None if not found.
    """
    target = proc_name.lower().removesuffix(".exe")
    dev = frida.get_local_device()        # works on Windows & other OSes
    for p in dev.enumerate_processes():
        name = Path(p.name).stem.lower()
        if name == target:
            return p.pid
    return None


def get_pid_of_lsass() -> int | None:
    """
    Get the PID of the Local Security Authority Subsystem Service (LSASS) process.
    
    Returns
    -------
    int | None
        PID of LSASS or None if not found.
    """
    return find_pid_by_name("lsass")  # LSASS is typically named "lsass.exe" on Windows


     
def are_we_running_on_windows() -> bool:
    """
    Pure Python check if the host system is Windows.
    This runs before spawning the target application.
    
    Returns:
        str: "Running on Windows" if the host system is Windows, 
                "Not running on Windows" otherwise.
    """
    if platform.system().lower() == "windows":
        return True
    else:
        return False
    
def supports_color(stream) -> bool:
        try:
            return (
                hasattr(stream, "isatty") and stream.isatty() and
                os.getenv("NO_COLOR") is None and
                os.getenv("TERM", "") not in ("", "dumb")
            )
        except Exception:
            return False


class CustomFormatter(logging.Formatter):
    """friTap prefix + optional ANSI colors (only when record._colorize=True)."""

    RESET = "\x1b[0m"
    COLORS = {
        logging.DEBUG:    "\x1b[95m",    # magenta
        logging.INFO:     "\x1b[32m",    # green
        logging.WARNING:  "\x1b[33m",    # yellow
        logging.ERROR:    "\x1b[31m",    # red
        logging.CRITICAL: "\x1b[31;1m",  # bright red
    }

    PREFIXES = {
        logging.INFO:     "[*]",
        logging.DEBUG:    "[!]",
        logging.WARNING:  "[-]",
        logging.ERROR:    "[-]",
        logging.CRITICAL: "[-]",
    }

    def __init__(self, *, use_color: bool = True):
        # we ignore parent fmt; we fully control the line format here
        super().__init__()
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        prefix = self.PREFIXES.get(record.levelno, "[*]")
        text = f"{prefix} {record.getMessage()}"
        if self.use_color and getattr(record, "_colorize", False):
            color = self.COLORS.get(record.levelno)
            if color:
                return f"{color}{text}{self.RESET}"
        return text