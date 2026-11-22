"""FIFO helpers shared by the sink and output-handler live stacks."""

from __future__ import annotations

import os
import tempfile
from typing import Optional, Tuple


def make_fifo(name: str) -> Tuple[str, str]:
    """Create a temp dir holding a FIFO called *name*; return (tmpdir, fifo_path)."""
    tmpdir = tempfile.mkdtemp()
    fifo_path = os.path.join(tmpdir, name)
    os.mkfifo(fifo_path)
    return tmpdir, fifo_path


def cleanup_fifo(fifo_path: Optional[str], tmpdir: Optional[str]) -> None:
    """Remove a FIFO and its temporary directory, ignoring missing files."""
    if fifo_path:
        try:
            os.unlink(fifo_path)
        except FileNotFoundError:
            pass
    if tmpdir:
        try:
            os.rmdir(tmpdir)
        except OSError:
            pass
