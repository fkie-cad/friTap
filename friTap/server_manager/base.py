#!/usr/bin/env python3

"""
Base class for cross-platform frida-server management.

Provides shared download/decompression logic and defines the interface
that platform-specific managers must implement. Downloads are verified
against GitHub's release-asset SHA-256 digest and fail closed (see
:mod:`friTap.server_manager.download`).
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Callable, Optional, Tuple

from friTap.fritap_utility import sha256_file

from .download import (
    ALLOW_UNVERIFIED_ENV,
    ServerDownloadError,
    ServerVerificationError,
    allow_unverified_from_env,
    asset_download_url,
    decompress_xz_bounded,
    download_verified,
    enforce_digest,
    fetch_asset_sha256,
    open_url,
    read_capped,
)
from .probe import ServerState, is_attach_capable, probe_frida_server

READINESS_POLL_INTERVAL = 0.5
MAX_CHECKSUM_FILE_BYTES = 4096


class BaseFridaServerManager(ABC):
    """Abstract base for platform-specific frida-server managers.

    Handles version-matched downloading and XZ decompression.
    Subclasses implement deployment, start/stop, and status checks.
    """

    def __init__(self) -> None:
        from friTap.backends import get_backend
        self._frida_version: str = get_backend().version
        self._logger = logging.getLogger(f"friTap.server_manager.{self.platform_name}")

    # ------------------------------------------------------------------
    # Abstract interface — platform-specific
    # ------------------------------------------------------------------

    @property
    @abstractmethod
    def platform_name(self) -> str:
        """Platform identifier used in download URLs (e.g. 'android', 'ios')."""
        ...

    @abstractmethod
    def detect_arch(self, device: Any = None) -> str:
        """Detect the target architecture (e.g. 'arm64', 'x86_64')."""
        ...

    @abstractmethod
    def deploy(self, binary_path: Path, device: Any = None) -> None:
        """Deploy the frida-server binary to the target."""
        ...

    @abstractmethod
    def start(self, device: Any = None) -> None:
        """Start frida-server on the target."""
        ...

    @abstractmethod
    def stop(self, device: Any = None) -> None:
        """Stop frida-server on the target."""
        ...

    @abstractmethod
    def is_running(self, device: Any = None) -> bool:
        """Check whether frida-server is currently running on the target."""
        ...

    @abstractmethod
    def needs_server(self) -> bool:
        """Whether this platform requires an explicit frida-server process.

        Local desktop platforms (macOS, Linux, Windows) typically do not;
        mobile/USB platforms (Android, iOS) do.
        """
        ...

    # ------------------------------------------------------------------
    # Shared logic — readiness
    # ------------------------------------------------------------------

    # Injectable for tests (patch on the instance).
    _sleep = staticmethod(time.sleep)
    _clock = staticmethod(time.monotonic)

    def ensure_running(
        self,
        device: Any,
        callback: Optional[Callable[[str], None]] = None,
        timeout: float = 15.0,
    ) -> ServerState:
        """Make *device* attach-capable and return the final probe state.

        Generic default: probe; if not attach-capable, ``start()`` and poll
        the probe until it is. Raises ``RuntimeError`` on timeout.
        """
        state = probe_frida_server(device)
        if is_attach_capable(state):
            return state
        if callback:
            callback("Starting frida-server ...")
        self.start(device)
        state = self._wait_until_attach_capable(lambda: probe_frida_server(device), timeout)
        if not is_attach_capable(state):
            raise RuntimeError(
                f"frida-server did not become reachable within {timeout:.0f}s "
                f"(last state: {state.value})"
            )
        return state

    def _wait_until_attach_capable(
        self,
        probe: Callable[[], ServerState],
        timeout: float,
    ) -> ServerState:
        """Poll *probe* until attach-capable or *timeout*; return the last state."""
        deadline = self._clock() + timeout
        state = probe()
        while not is_attach_capable(state) and self._clock() < deadline:
            self._sleep(READINESS_POLL_INTERVAL)
            state = probe()
        return state

    # ------------------------------------------------------------------
    # Shared logic — download & decompress
    # ------------------------------------------------------------------

    def _verify_download_hash(
        self,
        file_path: str,
        expected_url: Optional[str] = None,
        *,
        expected_sha256: Optional[str] = None,
    ) -> bool:
        """Verify the SHA256 hash of a downloaded file. Fails closed.

        Args:
            file_path: Path to the downloaded file.
            expected_url: Optional URL of a checksum file (``"<hex> [name]"``).
            expected_sha256: Expected hex digest; takes precedence over *expected_url*.

        Returns:
            True if the hash matched, or no expected hash was available and
            ``FRITAP_ALLOW_UNVERIFIED_SERVER=1`` is set. False otherwise; the
            file is then deleted.
        """
        computed_hash = sha256_file(file_path)
        self._logger.info("Downloaded file SHA256: %s", computed_hash)
        expected = expected_sha256 or self._fetch_checksum_file(expected_url)
        try:
            enforce_digest(Path(file_path).name, expected, computed_hash, allow_unverified_from_env())
        except ServerVerificationError as exc:
            self._logger.error("%s", exc)
            Path(file_path).unlink(missing_ok=True)
            return False
        return True

    def _fetch_checksum_file(self, url: Optional[str]) -> Optional[str]:
        """First token of the checksum file at *url*, or None if unavailable."""
        if not url:
            return None
        try:
            with open_url(url) as resp:
                body = read_capped(resp, MAX_CHECKSUM_FILE_BYTES, "checksum file")
            return body.decode().strip().split()[0]
        except (OSError, ValueError, IndexError, ServerDownloadError) as exc:
            self._logger.warning("Could not fetch checksum from %s: %s", url, exc)
            return None

    def _expected_sha256(self, filename: str) -> Tuple[Optional[str], str]:
        """Return (GitHub's digest for *filename* or None, why it may be missing)."""
        try:
            digest = fetch_asset_sha256(self._frida_version, filename)
        except (OSError, ValueError) as exc:
            self._logger.warning(
                "Could not fetch frida %s release metadata: %s", self._frida_version, exc,
            )
            return None, f"release metadata unavailable ({exc})"
        return digest, "GitHub publishes no sha256 digest for this asset"

    def download_server(
        self,
        arch: str,
        callback: Optional[Callable[[str], None]] = None,
    ) -> Path:
        """Download the version-matched frida-server binary.

        Args:
            arch: Target architecture (e.g. 'arm64', 'x86_64').
            callback: Optional progress callback receiving status strings.

        Returns:
            Path to the decompressed frida-server binary in a temp directory.

        Raises:
            ServerVerificationError: The SHA-256 digest GitHub records for the
                asset is missing or does not match (nothing is kept). Set
                ``FRITAP_ALLOW_UNVERIFIED_SERVER=1`` to accept a missing digest
                (frida releases published before June 2025).
            ServerDownloadError: Size cap exceeded or asset not in the release.
        """
        filename = f"frida-server-{self._frida_version}-{self.platform_name}-{arch}.xz"
        url = asset_download_url(self._frida_version, filename)

        self._logger.info("Downloading %s", url)
        if callback:
            callback(f"Downloading frida-server {self._frida_version} for {self.platform_name}-{arch}...")

        tmp_dir = Path(tempfile.mkdtemp(prefix="fritap_server_"))
        xz_path = tmp_dir / filename
        binary_path = tmp_dir / f"frida-server-{self._frida_version}-{self.platform_name}-{arch}"

        try:
            self._download_verified(url, xz_path, callback)
            self._decompress(xz_path, binary_path, callback)
        except Exception:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise

        if callback:
            callback("Download complete.")

        return binary_path

    def _download_verified(
        self,
        url: str,
        xz_path: Path,
        callback: Optional[Callable[[str], None]],
    ) -> None:
        """Stream *url* to *xz_path*; raise unless GitHub's digest for it matches."""
        try:
            expected, reason = self._expected_sha256(xz_path.name)
            allow_unverified = allow_unverified_from_env()
            if expected is None and allow_unverified and callback:
                callback(
                    f"WARNING: {xz_path.name} cannot be verified ({reason}); "
                    f"installing anyway because {ALLOW_UNVERIFIED_ENV}=1"
                )
            download_verified(url, xz_path, expected, allow_unverified, reason)
        except Exception as exc:
            self._logger.error("Download failed: %s", exc)
            if callback:
                callback(f"Download failed: {exc}")
            raise

    def _decompress(
        self,
        xz_path: Path,
        binary_path: Path,
        callback: Optional[Callable[[str], None]],
    ) -> None:
        """Bounded xz decompression to an executable *binary_path*; drops the .xz."""
        if callback:
            callback("Decompressing...")

        self._logger.info("Decompressing %s", xz_path)
        decompress_xz_bounded(xz_path, binary_path)

        # Make executable
        binary_path.chmod(0o755)

        # Clean up .xz
        xz_path.unlink()

    def install(
        self,
        device: Any = None,
        callback: Optional[Callable[[str], None]] = None,
    ) -> None:
        """Full install: detect arch, download, and deploy.

        Args:
            device: Frida device object (for USB/remote targets).
            callback: Optional progress callback.
        """
        arch = self.detect_arch(device)
        if callback:
            callback(f"Detected architecture: {arch}")

        binary = self.download_server(arch, callback)

        if callback:
            callback("Deploying to target...")

        self.deploy(binary, device)

        if callback:
            callback("Installation complete.")


_DEFAULT_UNIX_SERVER_PATH = Path("/tmp/frida-server")


class LocalUnixServerManager(BaseFridaServerManager, ABC):
    """Shared implementation for local Unix-like platforms (Linux, macOS).

    Provides identical deploy, start, stop, _kill_existing, and is_running
    logic. Subclasses only need to implement platform_name and detect_arch.
    """

    def deploy(self, binary_path: Path, device: Any = None) -> None:
        dest = _DEFAULT_UNIX_SERVER_PATH
        shutil.copy2(str(binary_path), str(dest))
        dest.chmod(0o755)
        self._logger.info("Deployed frida-server to %s", dest)

    def start(self, device: Any = None) -> None:
        self._kill_existing()
        try:
            subprocess.Popen(
                ["sudo", str(_DEFAULT_UNIX_SERVER_PATH), "-D"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self._logger.info("frida-server started")
        except Exception as exc:
            raise RuntimeError(f"Failed to start frida-server: {exc}")

    def stop(self, device: Any = None) -> None:
        self._kill_existing()
        self._logger.info("frida-server stopped")

    def _kill_existing(self) -> None:
        """Kill any running frida-server process."""
        try:
            subprocess.run(
                ["sudo", "killall", "frida-server"],
                capture_output=True,
                timeout=5,
            )
        except Exception:
            pass

    def is_running(self, device: Any = None) -> bool:
        try:
            result = subprocess.run(
                ["pgrep", "-x", "frida-server"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    def needs_server(self) -> bool:
        return False
