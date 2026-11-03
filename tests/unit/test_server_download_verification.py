#!/usr/bin/env python3

"""Unit tests for verified, bounded frida-server downloads.

``urllib.request.urlopen`` (as used by ``friTap.server_manager.download``) is
replaced by a fake; no network is used. The expected digest comes from the
``digest`` field of GitHub's release-asset metadata.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import lzma
import stat
import urllib.error
from unittest.mock import Mock, patch

import pytest

from friTap.server_manager import ServerDownloadError, ServerVerificationError
from friTap.server_manager import download as dl
from friTap.server_manager.base import BaseFridaServerManager

VERSION = "17.24.3"
ASSET = f"frida-server-{VERSION}-android-arm64.xz"
BINARY = b"\x7fELF fake frida-server " * 64
BODY = lzma.compress(BINARY)
GOOD_DIGEST = "sha256:" + hashlib.sha256(BODY).hexdigest()
URLOPEN = "friTap.server_manager.download.urllib.request.urlopen"
API_URL = dl.RELEASE_API_URL.format(version=VERSION)
ASSET_URL = dl.asset_download_url(VERSION, ASSET)


class _Manager(BaseFridaServerManager):
    """Concrete manager without frida backend / device dependencies."""

    platform_name = "android"

    def __init__(self) -> None:
        self._frida_version = VERSION
        self._logger = logging.getLogger("friTap.server_manager.test")

    def detect_arch(self, device=None):
        return "arm64"

    def deploy(self, binary_path, device=None):
        pass

    def start(self, device=None):
        pass

    def stop(self, device=None):
        pass

    def is_running(self, device=None):
        return False

    def needs_server(self):
        return False


class _Response(io.BytesIO):
    """BytesIO already supports ``with`` and ``read(n)`` like an HTTP response."""


def _release(digest=GOOD_DIGEST, name=ASSET):
    asset = {"name": name}
    if digest is not None:
        asset["digest"] = digest
    return {"tag_name": VERSION, "assets": [{"name": "frida-gadget.so"}, asset]}


def _fake_urlopen(release=None, body=BODY, api_error=None):
    """API URL -> release JSON (or *api_error*); any other URL -> *body*."""
    def urlopen(req, timeout=None):
        if req.full_url == API_URL:
            if api_error is not None:
                raise api_error
            return _Response(json.dumps(release).encode())
        return _Response(body)
    return Mock(side_effect=urlopen)


@pytest.fixture(autouse=True)
def _no_override_env(monkeypatch):
    monkeypatch.delenv(dl.ALLOW_UNVERIFIED_ENV, raising=False)


@pytest.fixture
def work_dir(tmp_path):
    """download_server's mkdtemp() directory, redirected under tmp_path."""
    target = tmp_path / "fritap_server_x"
    target.mkdir()
    with patch("friTap.server_manager.base.tempfile.mkdtemp", return_value=str(target)):
        yield target


def _download(urlopen_mock, callback=None):
    with patch(URLOPEN, urlopen_mock):
        return _Manager().download_server("arm64", callback)


# ---------------------------------------------------------------------------
# download_server: digest from GitHub release metadata, fail closed
# ---------------------------------------------------------------------------

class TestDownloadServer:
    def test_matching_digest_installs(self, work_dir):
        binary = _download(_fake_urlopen(_release()))
        assert binary.read_bytes() == BINARY
        assert binary.stat().st_mode & stat.S_IXUSR
        assert [p.name for p in work_dir.iterdir()] == [binary.name]  # no .xz / .part

    def test_requests_only_api_and_asset_urls(self, work_dir):
        urlopen = _fake_urlopen(_release())
        _download(urlopen)
        urls = [c.args[0].full_url for c in urlopen.call_args_list]
        assert urls == [API_URL, ASSET_URL]  # no same-origin .sha256 sidecar

    def test_mismatch_deletes_and_fails(self, work_dir):
        callback = Mock()
        with pytest.raises(ServerVerificationError) as exc:
            _download(_fake_urlopen(_release(digest="sha256:" + "0" * 64)), callback)
        msg = str(exc.value)
        assert ASSET in msg and "0" * 64 in msg and hashlib.sha256(BODY).hexdigest() in msg
        assert not work_dir.exists()
        assert any("Download failed" in c.args[0] for c in callback.call_args_list)

    def test_mismatch_not_overridable(self, work_dir, monkeypatch):
        monkeypatch.setenv(dl.ALLOW_UNVERIFIED_ENV, "1")
        with pytest.raises(ServerVerificationError):
            _download(_fake_urlopen(_release(digest="sha256:" + "0" * 64)))
        assert not work_dir.exists()

    def test_verification_error_is_runtime_error(self):
        assert issubclass(ServerVerificationError, RuntimeError)

    def test_missing_digest_fails_closed(self, work_dir):
        with pytest.raises(ServerVerificationError) as exc:
            _download(_fake_urlopen(_release(digest=None)))
        msg = str(exc.value)
        assert ASSET in msg and dl.ALLOW_UNVERIFIED_ENV in msg and "June 2025" in msg
        assert not work_dir.exists()

    def test_unknown_digest_algorithm_fails_closed(self, work_dir):
        with pytest.raises(ServerVerificationError):
            _download(_fake_urlopen(_release(digest="sha512:abcd")))

    def test_metadata_unreachable_fails_closed(self, work_dir):
        urlopen = _fake_urlopen(api_error=urllib.error.URLError("offline"))
        with pytest.raises(ServerVerificationError, match="metadata unavailable"):
            _download(urlopen)
        assert not work_dir.exists()

    def test_missing_digest_with_override_warns(self, work_dir, monkeypatch, caplog):
        monkeypatch.setenv(dl.ALLOW_UNVERIFIED_ENV, "1")
        callback = Mock()
        with caplog.at_level(logging.WARNING, logger=dl.logger.name):
            binary = _download(_fake_urlopen(_release(digest=None)), callback)
        assert binary.read_bytes() == BINARY
        assert "UNVERIFIED" in caplog.text and ASSET in caplog.text
        assert any("WARNING" in c.args[0] for c in callback.call_args_list)

    def test_asset_missing_from_release(self, work_dir):
        with pytest.raises(ServerDownloadError, match=ASSET):
            _download(_fake_urlopen(_release(name="other.xz")))
        assert not work_dir.exists()

    def test_timeout_on_every_request(self, work_dir):
        urlopen = _fake_urlopen(_release())
        _download(urlopen)
        assert urlopen.call_count == 2
        for call in urlopen.call_args_list:
            assert call.kwargs["timeout"] == dl.HTTP_TIMEOUT

    def test_binary_requested_without_content_encoding(self, work_dir):
        urlopen = _fake_urlopen(_release())
        _download(urlopen)
        req = urlopen.call_args_list[-1].args[0]
        assert req.get_header("Accept-encoding") == "identity"

    def test_oversized_metadata_rejected(self):
        with pytest.raises(ServerDownloadError, match="size cap"):
            dl.read_capped(io.BytesIO(b"x" * 11), 10, "release metadata")


# ---------------------------------------------------------------------------
# Size caps: streamed download and xz output
# ---------------------------------------------------------------------------

class TestSizeCaps:
    def test_oversize_download_aborted(self, tmp_path):
        dest = tmp_path / ASSET
        with patch(URLOPEN, _fake_urlopen(body=b"A" * 5000)):
            with pytest.raises(ServerDownloadError, match="size cap"):
                dl.download_verified(ASSET_URL, dest, None, True, max_bytes=4096)
        assert list(tmp_path.iterdir()) == []

    def test_download_within_cap_returns_digest(self, tmp_path):
        dest = tmp_path / ASSET
        with patch(URLOPEN, _fake_urlopen(body=BODY)):
            actual = dl.download_verified(ASSET_URL, dest, GOOD_DIGEST[7:], False)
        assert actual == GOOD_DIGEST[7:]
        assert dest.read_bytes() == BODY

    def test_xz_output_cap(self, tmp_path):
        src = tmp_path / "bomb.xz"
        src.write_bytes(lzma.compress(b"\0" * (3 * dl.CHUNK_SIZE)))
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        with pytest.raises(ServerDownloadError, match="size cap"):
            dl.decompress_xz_bounded(src, out_dir / "frida-server", max_bytes=dl.CHUNK_SIZE)
        assert list(out_dir.iterdir()) == []

    def test_xz_roundtrip(self, tmp_path):
        src = tmp_path / ASSET
        src.write_bytes(BODY)
        dst = tmp_path / "frida-server"
        dl.decompress_xz_bounded(src, dst)
        assert dst.read_bytes() == BINARY


# ---------------------------------------------------------------------------
# _verify_download_hash: kept for callers, now fail-closed
# ---------------------------------------------------------------------------

class TestVerifyDownloadHash:
    @pytest.fixture
    def asset_file(self, tmp_path):
        path = tmp_path / ASSET
        path.write_bytes(BODY)
        return path

    def test_expected_sha256_match(self, asset_file):
        assert _Manager()._verify_download_hash(str(asset_file), expected_sha256=GOOD_DIGEST[7:])
        assert asset_file.exists()

    def test_mismatch_returns_false_and_deletes(self, asset_file):
        assert not _Manager()._verify_download_hash(str(asset_file), expected_sha256="0" * 64)
        assert not asset_file.exists()

    def test_no_hash_fails_closed(self, asset_file):
        assert not _Manager()._verify_download_hash(str(asset_file))
        assert not asset_file.exists()

    def test_no_hash_with_override(self, asset_file, monkeypatch):
        monkeypatch.setenv(dl.ALLOW_UNVERIFIED_ENV, "true")
        assert _Manager()._verify_download_hash(str(asset_file))

    def test_checksum_url_failure_fails_closed(self, asset_file):
        urlopen = Mock(side_effect=urllib.error.URLError("404"))
        with patch(URLOPEN, urlopen):
            assert not _Manager()._verify_download_hash(str(asset_file), "https://x/a.sha256")
        assert urlopen.call_args.kwargs["timeout"] == dl.HTTP_TIMEOUT

    def test_checksum_url_match(self, asset_file):
        body = f"{GOOD_DIGEST[7:]}  {ASSET}\n".encode()
        with patch(URLOPEN, Mock(return_value=_Response(body))):
            assert _Manager()._verify_download_hash(str(asset_file), "https://x/a.sha256")


@pytest.mark.parametrize("digest,expected", [
    ("sha256:" + "AB" * 32, "ab" * 32),
    ("sha256:" + "ab" * 31, None),
    ("md5:" + "ab" * 16, None),
    ("", None),
    (None, None),
])
def test_parse_sha256_digest(digest, expected):
    assert dl.parse_sha256_digest(digest) == expected


@pytest.mark.parametrize("value,expected", [
    ("1", True), ("TRUE", True), ("yes", True), ("0", False), ("", False),
])
def test_allow_unverified_from_env(monkeypatch, value, expected):
    monkeypatch.setenv(dl.ALLOW_UNVERIFIED_ENV, value)
    assert dl.allow_unverified_from_env() is expected
