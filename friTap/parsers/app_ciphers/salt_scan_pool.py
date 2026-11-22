"""Run the AppLovin salt sliding-window scan over ``python -m`` worker subprocesses.

``multiprocessing`` (spawn start method, the macOS/Windows default) makes
every worker re-execute the caller's ``__main__`` script, so a user script
without an ``if __name__ == "__main__":`` guard re-ran itself once per
worker.  Here each worker is a plain ``sys.executable -m
friTap.parsers.app_ciphers.salt_scan_worker`` process that imports only
friTap, never the caller's script.

The padded blob is written once to a private (0600) temp file inside a
private temp directory; each worker mmaps it and reads only the chunks it
is handed.  Chunks are dispatched lowest offset first over the workers'
stdin as they become free (load balancing across fast/slow cores), and
nothing above a known hit is dispatched.  The result always equals the
serial scan's: a hit counts only once every lower chunk is known to be
empty.  Chunks no worker reported (launch error, crash, bad output,
timeout) are scanned serially with the caller-supplied range scanner.
"""

from __future__ import annotations

import logging
import os
import queue
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass, field
from typing import IO, Callable, Iterator

logger = logging.getLogger("friTap.parsers.app_ciphers.salt_scan_pool")

WORKER_MODULE = "friTap.parsers.app_ciphers.salt_scan_worker"
# Give up on the workers if none reports anything for this long (seconds).
WORKER_IDLE_TIMEOUT = 300.0
# Chunks queued per worker at once (hides the report/dispatch round trip).
WORKER_PIPELINE_DEPTH = 2
_NO_HIT = "-"
_EOF = None

# ``(data, base_offset, count, target) -> absolute hit offset | None`` (serial scan).
RangeScanner = Callable[[bytes, int, int, bytes], "int | None"]


def friTap_import_root() -> str:
    """The directory that contains the ``friTap`` package (for ``PYTHONPATH``)."""
    import friTap

    return os.path.dirname(os.path.dirname(os.path.abspath(friTap.__file__)))


def worker_environment() -> dict[str, str]:
    """The parent environment with friTap's import root prepended to ``PYTHONPATH``."""
    env = dict(os.environ)
    paths = [friTap_import_root()] + [p for p in env.get("PYTHONPATH", "").split(os.pathsep) if p]
    env["PYTHONPATH"] = os.pathsep.join(paths)
    return env


def worker_command(blob_path: str, target: bytes) -> list[str]:
    return [sys.executable, "-m", WORKER_MODULE, blob_path, target.hex()]


@dataclass(eq=False)
class _Worker:
    index: int
    process: subprocess.Popen
    stderr_path: str
    in_flight: set[int] = field(default_factory=set)
    failed: bool = False

    def assign(self, start: int, count: int) -> bool:
        """Send one chunk; False (and the worker marked failed) if the pipe is gone."""
        try:
            self.process.stdin.write(f"{start} {count}\n".encode("ascii"))
            self.process.stdin.flush()
        except (OSError, ValueError) as exc:
            logger.debug("Salt-scan worker %d stopped accepting work: %s", self.index, exc)
            self.fail()
            return False
        self.in_flight.add(start)
        return True

    def finish_input(self) -> None:
        """Close stdin: the worker exits after its in-flight chunks."""
        try:
            self.process.stdin.close()
        except OSError:
            pass

    def fail(self) -> None:
        self.failed = True
        self.kill()

    def kill(self) -> None:
        if self.process.poll() is None:
            self.process.kill()

    def stderr_tail(self, limit: int = 500) -> str:
        try:
            with open(self.stderr_path, "rb") as handle:
                return handle.read()[-limit:].decode("utf-8", "replace").strip()
        except OSError:
            return ""


@dataclass
class _ChunkResults:
    """Per-chunk outcomes: absent = unknown, None = no hit, int = hit offset."""

    total: int
    chunk: int
    outcomes: dict[int, "int | None"] = field(default_factory=dict)

    def starts(self) -> range:
        return range(0, self.total, self.chunk)

    def count_at(self, start: int) -> int:
        return min(self.chunk, self.total - start)

    def record(self, start: int, hit: "int | None") -> None:
        if start % self.chunk or not 0 <= start < self.total:
            raise ValueError(f"unknown chunk start {start}")
        if hit is not None and not start <= hit < start + self.count_at(start):
            raise ValueError(f"hit {hit} outside chunk {start}")
        self.outcomes[start] = hit

    def best_hit(self) -> "int | None":
        hits = [hit for hit in self.outcomes.values() if hit is not None]
        return min(hits) if hits else None

    def decided(self) -> tuple[bool, "int | None"]:
        """``(True, offset|None)`` once the lowest hit (or no hit at all) is certain."""
        for start in self.starts():
            if start not in self.outcomes:
                return False, None
            if self.outcomes[start] is not None:
                return True, self.outcomes[start]
        return True, None


def _parse_report(line: bytes) -> tuple[int, "int | None"]:
    start_text, hit_text = line.decode("ascii").split()
    return int(start_text), None if hit_text == _NO_HIT else int(hit_text)


def _pump_lines(worker: _Worker, stream: IO[bytes], sink: "queue.Queue") -> None:
    """Reader thread: forward each stdout line of *worker*, then an EOF marker."""
    try:
        for line in stream:
            sink.put((worker, line))
    except (OSError, ValueError):
        pass
    finally:
        sink.put((worker, _EOF))


class SubprocessWindowScan:
    """One parallel scan of a padded blob; see the module docstring."""

    def __init__(self, padded: bytes, total: int, target: bytes, workers: int, chunk: int,
                 serial_scan: RangeScanner, overlap: int,
                 idle_timeout: float = WORKER_IDLE_TIMEOUT) -> None:
        self.padded, self.target = padded, target
        self.overlap, self.serial_scan = overlap, serial_scan
        self.results = _ChunkResults(total, chunk)
        self.workers = max(1, min(workers, len(self.results.starts())))
        self.idle_timeout = idle_timeout
        self.healthy = False  # True once any worker reported a valid result
        self._undispatched: Iterator[int] = iter(self.results.starts())
        self._next_start: "int | None" = next(self._undispatched, None)

    def run(self) -> "int | None":
        """Absolute offset of the lowest matching window, or None."""
        with tempfile.TemporaryDirectory(prefix="fritap-salt-scan-") as workdir:
            launched: list[_Worker] = []
            try:
                sink = self._launch_all(self._write_blob(workdir), workdir, launched)
                self._collect(sink, launched)
            finally:
                _stop_all(launched)
        return self._finish_serially()

    def _write_blob(self, workdir: str) -> str:
        fd, path = tempfile.mkstemp(prefix="blob-", suffix=".bin", dir=workdir)  # mode 0600
        with os.fdopen(fd, "wb") as handle:
            handle.write(self.padded)
        return path

    def _launch_all(self, blob_path: str, workdir: str, launched: list[_Worker]) -> "queue.Queue":
        sink: queue.Queue = queue.Queue()
        env = worker_environment()
        for index in range(self.workers):
            worker = self._launch(index, blob_path, workdir, env)
            if worker is not None:
                launched.append(worker)
                threading.Thread(target=_pump_lines, args=(worker, worker.process.stdout, sink),
                                 name=f"salt-scan-reader-{index}", daemon=True).start()
        return sink

    def _launch(self, index: int, blob_path: str, workdir: str, env: dict) -> "_Worker | None":
        stderr_path = os.path.join(workdir, f"worker-{index}.err")
        try:
            with open(stderr_path, "wb") as stderr:
                process = subprocess.Popen(worker_command(blob_path, self.target), stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE, stderr=stderr, cwd=workdir, env=env)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            logger.debug("Salt-scan worker %d failed to start: %s", index, exc)
            return None
        return _Worker(index, process, stderr_path)

    def _collect(self, sink: "queue.Queue", workers: list[_Worker]) -> None:
        """Dispatch chunks and consume reports until decided or every worker ended."""
        for worker in workers:
            self._refill(worker, WORKER_PIPELINE_DEPTH)
        live = len(workers)
        while live and not self.results.decided()[0]:
            try:
                worker, line = sink.get(timeout=self.idle_timeout)
            except queue.Empty:
                logger.debug("Salt-scan workers idle for %.0fs; finishing serially", self.idle_timeout)
                return
            if line is _EOF:
                live -= 1
                self._check_exit(worker)
            elif self._handle_line(worker, line):
                self._refill(worker, 1)

    def _take_chunk(self) -> "int | None":
        """Lowest undispatched chunk start, unless it lies above a known hit."""
        start, best = self._next_start, self.results.best_hit()
        if start is None or (best is not None and start > best):
            return None
        self._next_start = next(self._undispatched, None)
        return start

    def _refill(self, worker: _Worker, slots: int) -> None:
        for _ in range(slots):
            start = self._take_chunk()
            if start is None:
                break
            if not worker.assign(start, self.results.count_at(start)):
                return
        if not worker.in_flight:
            worker.finish_input()

    def _handle_line(self, worker: _Worker, line: bytes) -> bool:
        """Record one report; False if the worker is (now) considered broken."""
        if worker.failed:
            return False
        try:
            start, hit = _parse_report(line)
            if start not in worker.in_flight:
                raise ValueError(f"chunk {start} was not assigned to this worker")
            self.results.record(start, hit)
        except (ValueError, UnicodeDecodeError) as exc:
            logger.debug("Salt-scan worker %d sent bad output %r: %s", worker.index, line[:80], exc)
            worker.fail()
            return False
        worker.in_flight.discard(start)
        self.healthy = True
        return True

    def _check_exit(self, worker: _Worker) -> None:
        try:
            code = worker.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            worker.kill()
            code = worker.process.wait()
        if code != 0 and not worker.failed:
            logger.debug("Salt-scan worker %d exited with %s: %s", worker.index, code, worker.stderr_tail())
            worker.failed = True

    def _finish_serially(self) -> "int | None":
        """Fill in unreported chunks with the serial scan until the answer is decided."""
        while not self.results.decided()[0]:
            start = next(s for s in self.results.starts() if s not in self.results.outcomes)
            count = self.results.count_at(start)
            logger.debug("Salt-scan chunk at %d not reported by a worker; scanning serially", start)
            data = self.padded[start:start + count + self.overlap]
            self.results.record(start, self.serial_scan(data, start, count, self.target))
        return self.results.decided()[1]


def _stop_all(workers: list[_Worker]) -> None:
    """Kill every still-running worker and reap all of them (no zombies, no leaked pipes)."""
    for worker in workers:
        worker.kill()
    for worker in workers:
        try:
            worker.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            logger.debug("Salt-scan worker %d did not exit after kill", worker.index)
        for stream in (worker.process.stdin, worker.process.stdout):
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                pass
