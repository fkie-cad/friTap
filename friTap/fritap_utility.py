#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pathlib import Path
import frida
import platform

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