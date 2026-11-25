"""Deterministic tests for the native perf transport helpers, without BPF privileges."""

import shutil
import subprocess
from pathlib import Path

import pytest


def test_native_perf_order_and_loss(tmp_path):
    cc = shutil.which("cc")
    if cc is None:
        pytest.skip("requires a C compiler")
    root = Path(__file__).resolve().parents[2]
    binary = tmp_path / "perf-order"
    subprocess.run(
        [cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-I", root / "agent_ebpf",
         Path(__file__).with_name("ebpf_perf_order.c"), "-o", binary],
        check=True, timeout=30,
    )
    subprocess.run([binary], check=True, timeout=10)
