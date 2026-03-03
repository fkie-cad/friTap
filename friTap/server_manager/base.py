#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Base class for cross-platform frida-server management.

Provides shared download/decompression logic and defines the interface
that platform-specific managers must implement.
"""

from __future__ import annotations

import hashlib
import lzma
import logging
import shutil
import subprocess
import tempfile
import urllib.request
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Callable, Optional


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
    # Shared logic — download & decompress
    # ------------------------------------------------------------------

    def _verify_download_hash(self, file_path: str, expected_url: Optional[str] = None) -> bool:
        """Verify SHA256 hash of a downloaded file.

        Args:
            file_path: Path to the downloaded file.
            expected_url: Optional URL to fetch expected hash from.

        Returns:
            True if verification passed or was skipped, False if mismatch.
        """
        # Compute hash of downloaded file
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        computed_hash = sha256.hexdigest()
        self._logger.info("Downloaded file SHA256: %s", computed_hash)

        if expected_url:
            try:
                req = urllib.request.Request(expected_url)
                req.add_header("User-Agent", "friTap")
                with urllib.request.urlopen(req, timeout=10) as resp:
                    expected_hash = resp.read().decode().strip().split()[0]
                if computed_hash != expected_hash:
                    self._logger.error(
                        "Hash mismatch! Expected %s, got %s",
                        expected_hash, computed_hash,
                    )
                    return False
                self._logger.info("Hash verification passed")
            except Exception as e:
                self._logger.warning("Could not verify download hash: %s", e)
        else:
            self._logger.warning(
                "No checksum URL provided; skipping hash verification. "
                "Manual verification hash: %s", computed_hash,
            )
        return True

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
        """
        filename = f"frida-server-{self._frida_version}-{self.platform_name}-{arch}.xz"
        url = (
            f"https://github.com/frida/frida/releases/download/"
            f"{self._frida_version}/{filename}"
        )

        self._logger.info("Downloading %s", url)
        if callback:
            callback(f"Downloading frida-server {self._frida_version} for {self.platform_name}-{arch}...")

        tmp_dir = Path(tempfile.mkdtemp(prefix="fritap_server_"))
        xz_path = tmp_dir / filename
        binary_path = tmp_dir / f"frida-server-{self._frida_version}-{self.platform_name}-{arch}"

        try:
            urllib.request.urlretrieve(url, str(xz_path))
        except Exception as exc:
            self._logger.error("Download failed: %s", exc)
            if callback:
                callback(f"Download failed: {exc}")
            raise

        # Verify download integrity via SHA256 hash
        checksum_url = (
            f"https://github.com/frida/frida/releases/download/"
            f"{self._frida_version}/{filename}.sha256"
        )
        if not self._verify_download_hash(str(xz_path), checksum_url):
            raise RuntimeError(
                f"SHA256 hash verification failed for {filename}. "
                "The downloaded file may be corrupted or tampered with."
            )

        if callback:
            callback("Decompressing...")

        self._logger.info("Decompressing %s", xz_path)
        with lzma.open(xz_path) as compressed:
            binary_path.write_bytes(compressed.read())

        # Make executable
        binary_path.chmod(0o755)

        # Clean up .xz
        xz_path.unlink()

        if callback:
            callback("Download complete.")

        return binary_path

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
