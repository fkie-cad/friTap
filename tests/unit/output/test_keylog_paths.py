#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Tests for the per-protocol keylog filename splitter."""

import pytest

from friTap.output.keylog_paths import split_keylog_path


class TestSplitKeylogPath:
    def test_simple_extension(self):
        assert split_keylog_path("mykeys.log", "ssh") == "mykeys.ssh.log"
        assert split_keylog_path("mykeys.log", "tls") == "mykeys.tls.log"

    def test_no_extension(self):
        assert split_keylog_path("mykeys", "ssh") == "mykeys.ssh"

    def test_directory_preserved(self):
        assert split_keylog_path("/path/to/keys.log", "ssh") == "/path/to/keys.ssh.log"
        assert split_keylog_path("./relative/keys.log", "ssh") == "./relative/keys.ssh.log"

    def test_directory_no_extension(self):
        assert split_keylog_path("/path/to/keys", "ssh") == "/path/to/keys.ssh"

    def test_multi_dot_uses_last_dot_only(self):
        """``os.path.splitext`` semantics: only the LAST '.' is the extension."""
        assert split_keylog_path("keys.tar.gz", "ssh") == "keys.tar.ssh.gz"
        assert split_keylog_path("my.app.keys.log", "ssh") == "my.app.keys.ssh.log"

    def test_dotfile_no_extension(self):
        """``splitext('.keylog')`` returns ``('', '.keylog')`` — treat as no-ext stem."""
        assert split_keylog_path(".keylog", "ssh") == ".keylog.ssh"

    def test_dotfile_with_extension(self):
        assert split_keylog_path(".hidden.log", "ssh") == ".hidden.ssh.log"

    def test_empty_input(self):
        assert split_keylog_path("", "ssh") == ".ssh"

    def test_different_protocols(self):
        assert split_keylog_path("k.log", "ipsec") == "k.ipsec.log"
        assert split_keylog_path("k.log", "quic") == "k.quic.log"

    @pytest.mark.parametrize(
        "base,protocol,expected",
        [
            ("mykeys.log", "ssh", "mykeys.ssh.log"),
            ("mykeys.log", "tls", "mykeys.tls.log"),
            ("mykeys", "ssh", "mykeys.ssh"),
            ("/p/keys.log", "ssh", "/p/keys.ssh.log"),
            ("keys.tar.gz", "ssh", "keys.tar.ssh.gz"),
            (".keylog", "ssh", ".keylog.ssh"),
            ("", "ssh", ".ssh"),
        ],
    )
    def test_docstring_examples(self, base, protocol, expected):
        assert split_keylog_path(base, protocol) == expected
