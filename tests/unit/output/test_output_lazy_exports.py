#!/usr/bin/env python3

"""``friTap.output`` exports its handlers lazily (PEP 562).

Protocol, plugin and offline modules import the light
``friTap.output.keylog_format`` validators. That must not drag in the heavy
handlers (``pcapng_handler`` -> ``friTap.sinks`` -> schemas -> pydantic), yet
every exported name must stay importable via ``from friTap.output import X``.
Import-isolation checks run in a fresh interpreter: the test session has
already imported most of friTap.
"""

import subprocess
import sys
from pathlib import Path

import pytest

import friTap.output as output_pkg

REPO_ROOT = Path(__file__).resolve().parents[3]

EXPORTED_NAMES = (
    "OutputHandler",
    "PcapOutputHandler",
    "KeylogOutputHandler",
    "KeylogFormatter",
    "JsonOutputHandler",
    "JsonlOutputHandler",
    "ConsoleOutputHandler",
    "LiveWiresharkHandler",
    "PcapngOutputHandler",
    "LivePcapngHandler",
    "LiveAutoDecryptHandler",
    "KeyCollectorHandler",
    "OutputHandlerFactory",
)


def _run_fresh(code: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", code], cwd=REPO_ROOT,
        capture_output=True, text=True, timeout=120,
    )


def test_all_lists_every_exported_name():
    assert sorted(output_pkg.__all__) == sorted(EXPORTED_NAMES)
    assert sorted(output_pkg._LAZY_EXPORTS) == sorted(EXPORTED_NAMES)


@pytest.mark.parametrize("name", EXPORTED_NAMES)
def test_name_importable_from_package(name):
    namespace: dict = {}
    exec(f"from friTap.output import {name}", namespace)
    cls = namespace[name]
    assert cls.__name__ == name
    assert cls.__module__.startswith("friTap.output.")
    assert getattr(output_pkg, name) is cls


def test_lazy_name_resolves_to_defining_submodule_class():
    from friTap.output.pcapng_handler import PcapngOutputHandler
    assert output_pkg.PcapngOutputHandler is PcapngOutputHandler


def test_submodules_still_importable_via_from_import():
    from friTap.output import keylog_format, shared_keylog_writer
    assert keylog_format.__name__ == "friTap.output.keylog_format"
    assert shared_keylog_writer.__name__ == "friTap.output.shared_keylog_writer"


def test_unknown_attribute_raises_attribute_error():
    with pytest.raises(AttributeError, match="no attribute 'NoSuchHandler'"):
        output_pkg.NoSuchHandler  # noqa: B018
    with pytest.raises(ImportError):
        exec("from friTap.output import NoSuchHandler", {})


def test_dir_lists_lazy_names():
    listing = dir(output_pkg)
    assert set(EXPORTED_NAMES) <= set(listing)


def test_keylog_format_import_does_not_load_heavy_handlers():
    result = _run_fresh(
        "import sys, friTap.output.keylog_format\n"
        "heavy = [m for m in ('friTap.output.pcapng_handler', 'friTap.sinks', 'pydantic')"
        " if m in sys.modules]\n"
        "print(heavy)\n"
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "[]"


def test_every_name_importable_in_fresh_interpreter():
    names = ", ".join(EXPORTED_NAMES)
    result = _run_fresh(f"from friTap.output import {names}\nprint('ok')\n")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"
