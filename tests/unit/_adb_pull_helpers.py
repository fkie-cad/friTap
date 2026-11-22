"""Test doubles for the tracked ``adb pull`` (``Android._adb_pull_file``).

The pull runs as an ``ADB.Popen`` process (not ``ADB.run``) so a forced exit can
kill it and the force-exit timer can watch it progress (D7).
"""

from __future__ import annotations

from unittest.mock import MagicMock


def fake_pull_process(returncode=0, stdout="", stderr="", raises=None):
    """A finished ``adb pull`` Popen double; *raises* makes communicate() raise."""
    process = MagicMock()
    process.args = ["adb", "pull"]
    process.returncode = returncode
    process.poll.return_value = returncode
    if raises is not None:
        process.communicate.side_effect = raises
    else:
        process.communicate.return_value = (stdout, stderr)
    return process


def reply_to_pull(android, returncode=0, stdout="", stderr="1 file pulled", raises=None):
    """Make ``android.adb`` (a MagicMock) answer the next pull like this."""
    process = fake_pull_process(returncode, stdout, stderr, raises)
    android.adb.Popen.return_value = process
    return process


def pull_timeout(android):
    """The timeout the last pull was given."""
    return android.adb.Popen.return_value.communicate.call_args.kwargs["timeout"]
