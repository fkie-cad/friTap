"""The parallel AppLovin salt scan must not re-run an unguarded caller script.

Regression: the old ``ProcessPoolExecutor`` used the spawn start method on
macOS, so every worker re-executed the caller's ``__main__`` -- a script
without an ``if __name__ == "__main__":`` guard ran once per worker.
"""

from __future__ import annotations

import os
import random
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from friTap.parsers.app_ciphers import applovin_keys as ak
from friTap.parsers.app_ciphers import salt_scan_pool as pool_mod

REPO_ROOT = Path(__file__).resolve().parents[2]
SALT21 = bytes(range(0xA1, 0xA1 + 21))
SALT32 = SALT21 + bytes(11)
PROTOCOL_ID = ak.protocol_id_for_salt(SALT32)
TARGET = bytes.fromhex(PROTOCOL_ID)
CHUNK = 1000

# No main guard on purpose.  Each execution appends to the marker file.
UNGUARDED_SCRIPT = textwrap.dedent('''
    import os, random, zipfile
    from friTap.parsers.app_ciphers import applovin_keys as ak

    with open(os.environ["MARKER_FILE"], "a") as marker:
        marker.write("ran\\n")

    parallel = []
    _scan = ak._WindowScanner.scan
    def counting_scan(self, blob, target):
        result = _scan(self, blob, target)
        parallel.append(self.parallel_scans)
        return result
    ak._WindowScanner.scan = counting_scan

    salt21 = bytes(range(0xA1, 0xA1 + 21))
    protocol_id = ak.protocol_id_for_salt(salt21 + bytes(11))
    blob = bytearray(random.Random(5).randbytes(ak.PARALLEL_MIN_BLOB_BYTES + 4096))
    offset = 2 * ak.PARALLEL_CHUNK_OFFSETS - 9          # straddles a chunk boundary
    blob[offset:offset + 21] = salt21
    print("SALT", ak.recover_salt([bytes(blob)], protocol_id).hex())

    with zipfile.ZipFile(os.environ["APK_FILE"], "w") as zf:
        zf.writestr("classes.dex", b"dex\\n" + bytes(blob))
    print("BUNDLE", ak.recover_salt_from_bundle(os.environ["APK_FILE"], protocol_id).hex())
    print("PARALLEL", sum(parallel))
''')


def _run_unguarded(tmp_path: Path, via_stdin: bool) -> tuple[subprocess.CompletedProcess, Path]:
    script = tmp_path / "unguarded.py"
    script.write_text(UNGUARDED_SCRIPT)
    marker = tmp_path / "marker.txt"
    env = dict(os.environ, PYTHONPATH=str(REPO_ROOT), MARKER_FILE=str(marker),
               APK_FILE=str(tmp_path / "app.apk"))
    env[ak.ENV_SCAN_WORKERS] = "3"
    if via_stdin:
        result = subprocess.run([sys.executable, "-"], input=script.read_text(), capture_output=True,
                                text=True, cwd=tmp_path, env=env, timeout=120)
    else:
        result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True,
                                cwd=tmp_path, env=env, timeout=120)
    return result, marker


@pytest.mark.parametrize("via_stdin", [False, True], ids=["script-file", "stdin"])
def test_unguarded_caller_script_runs_exactly_once(tmp_path, via_stdin):
    result, marker = _run_unguarded(tmp_path, via_stdin)
    assert result.returncode == 0, result.stderr
    assert "Traceback" not in result.stderr
    assert f"SALT {SALT32.hex()}" in result.stdout
    assert f"BUNDLE {SALT32.hex()}" in result.stdout
    assert "PARALLEL 2" in result.stdout  # both scans really used worker subprocesses
    assert marker.read_text() == "ran\n"


def _blob_with_salt(size: int, offset: int) -> bytes:
    data = bytearray(random.Random(11).randbytes(size))
    data[offset:offset + 21] = SALT21
    return bytes(data)


def _fake_worker(monkeypatch, code: str) -> None:
    monkeypatch.setattr(pool_mod, "worker_command", lambda path, target: [sys.executable, "-c", code, path, target.hex()])


def test_garbage_worker_output_falls_back_to_serial(monkeypatch, capfd):
    _fake_worker(monkeypatch, "import sys; sys.stdin.readline(); print('garbage', flush=True); sys.exit(3)")
    scanner = ak._WindowScanner(workers=3, min_parallel_bytes=1, chunk=CHUNK)
    assert scanner.scan(_blob_with_salt(5000, 2 * CHUNK - 4), TARGET) == SALT32
    assert scanner._parallel_ok is False and scanner.parallel_scans == 0
    assert "Traceback" not in capfd.readouterr().err


def test_crashing_worker_falls_back_to_serial(monkeypatch, capfd):
    _fake_worker(monkeypatch, "raise SystemExit('boom')")
    assert ak._WindowScanner(workers=2, min_parallel_bytes=1, chunk=CHUNK).scan(
        _blob_with_salt(4000, 3500), TARGET) == SALT32
    assert "Traceback" not in capfd.readouterr().err


def test_worker_dying_mid_scan_only_its_ranges_go_serial(monkeypatch, capfd):
    # Answers its first chunk correctly, then dies: the rest must still be found.
    _fake_worker(monkeypatch, textwrap.dedent('''
        import mmap, sys
        from friTap.parsers.app_ciphers.salt_scan_worker import scan_chunk
        with open(sys.argv[1], "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as view:
            start, count = map(int, sys.stdin.readline().split())
            print(scan_chunk(view, start, count, bytes.fromhex(sys.argv[2])), flush=True)
        sys.exit(1)
    '''))
    monkeypatch.setenv("PYTHONPATH", str(REPO_ROOT))
    blob = _blob_with_salt(8000, 6 * CHUNK + 3)
    scan = pool_mod.SubprocessWindowScan(ak._padded_for_windows(blob), len(blob), TARGET, 2, CHUNK,
                                         serial_scan=ak._scan_window_range, overlap=20)
    assert scan.run() == 6 * CHUNK + 3
    assert scan.healthy
    assert "Traceback" not in capfd.readouterr().err


def test_hung_workers_time_out_and_are_killed(monkeypatch, tmp_path):
    _fake_worker(monkeypatch, "import time; time.sleep(60)")
    monkeypatch.setattr(pool_mod.tempfile, "tempdir", str(tmp_path))
    launched = []
    real_popen = pool_mod.subprocess.Popen
    monkeypatch.setattr(pool_mod.subprocess, "Popen", lambda *a, **k: launched.append(real_popen(*a, **k)) or launched[-1])
    blob = _blob_with_salt(3000, 2500)
    scan = pool_mod.SubprocessWindowScan(ak._padded_for_windows(blob), len(blob), TARGET, 2, CHUNK,
                                         serial_scan=ak._scan_window_range, overlap=20, idle_timeout=0.5)
    assert scan.run() == 2500
    assert len(launched) == 2 and all(p.returncode is not None for p in launched)
    assert list(tmp_path.iterdir()) == []  # temp blob + directory removed


def test_lowest_offset_wins_like_serial():
    blob = bytearray(_blob_with_salt(9000, 7 * CHUNK + 1))
    blob[2 * CHUNK + 990:2 * CHUNK + 1011] = SALT21  # lower hit, straddling a boundary
    scan = pool_mod.SubprocessWindowScan(ak._padded_for_windows(bytes(blob)), len(blob), TARGET, 4, CHUNK,
                                         serial_scan=ak._scan_window_range, overlap=20)
    assert scan.run() == 2 * CHUNK + 990 == ak._scan_window_range(ak._padded_for_windows(bytes(blob)), 0, len(blob), TARGET)
    assert scan.healthy


def test_worker_environment_makes_friTap_importable(monkeypatch):
    monkeypatch.setenv("PYTHONPATH", "/elsewhere")
    paths = pool_mod.worker_environment()["PYTHONPATH"].split(os.pathsep)
    assert paths == [str(REPO_ROOT), "/elsewhere"]


def test_worker_serve_protocol():
    import io

    from friTap.parsers.app_ciphers import salt_scan_worker as worker

    padded = ak._padded_for_windows(_blob_with_salt(3000, 1990))
    out = io.StringIO()
    worker.serve(padded, TARGET, io.StringIO("0 1000\n1000 1000\n2000 1000\n"), out)
    assert out.getvalue().splitlines() == ["0 -", "1000 1990", "2000 -"]
