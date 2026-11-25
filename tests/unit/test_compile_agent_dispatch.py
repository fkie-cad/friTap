"""Exercise build target dispatch without requiring either native toolchain."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "dev" / "compile_agent.sh"

pytestmark = pytest.mark.skipif(os.name == "nt", reason="Unix build script")

BRIDGE_INSTALL = "frida-pm install frida-objc-bridge frida-java-bridge"
DEFAULT_FRIDA_BUILD = [
    BRIDGE_INSTALL,
    "frida-compile agent/fritap_agent.ts -o friTap/fritap_agent.js",
    "frida-compile agent/memory_scan_agent.ts -o friTap/fritap_memscan.js",
]
EBPF_BUILD = ["make -C agent_ebpf"]

STUB_TOOLS = {
    "uname": 'printf "%s\\n" Linux',
    "make": 'printf "make %s\\n" "$*" >> "$BUILD_TEST_LOG"',
    "frida-pm": 'printf "frida-pm %s\\n" "$*" >> "$BUILD_TEST_LOG"',
    "frida-compile": """
printf 'frida-compile %s\\n' "$*" >> "$BUILD_TEST_LOG"
mkdir -p "$(dirname "$3")"
printf built > "$3"
""",
}


def _install_stub_tools(tools: Path) -> None:
    tools.mkdir()
    for tool, body in STUB_TOOLS.items():
        executable = tools / tool
        executable.write_text(f"#!/bin/sh\nset -eu\n{body}\n")
        executable.chmod(0o755)


@pytest.fixture
def run_build(tmp_path, monkeypatch):
    """Run a copy of compile_agent.sh with stubbed tools; return invocations."""
    dev = tmp_path / "checkout with spaces" / "dev"
    dev.mkdir(parents=True)
    script = dev / SCRIPT.name
    shutil.copy2(SCRIPT, script)

    tools = tmp_path / "tools"
    _install_stub_tools(tools)
    log = tmp_path / "invocations"
    monkeypatch.setenv("BUILD_TEST_LOG", str(log))
    monkeypatch.setenv("PATH", f"{tools}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.delenv("ENTRY", raising=False)
    monkeypatch.delenv("OUT", raising=False)

    def run(args, **env):
        for name, value in env.items():
            monkeypatch.setenv(name, value)
        subprocess.run([script, *args], cwd=tmp_path, check=True, timeout=10)
        return log.read_text().splitlines()

    return run


@pytest.mark.parametrize("args,expected", [
    ([], DEFAULT_FRIDA_BUILD),
    (["frida"], DEFAULT_FRIDA_BUILD),
    (["both"], DEFAULT_FRIDA_BUILD),
    (["all"], DEFAULT_FRIDA_BUILD),
    (["ebpf"], EBPF_BUILD),
])
def test_compile_agent_dispatch(run_build, args, expected):
    assert run_build(args) == expected


@pytest.mark.parametrize("args", [[], ["ebpf"], ["frida"], ["intercept"], ["bogus"]])
def test_entry_out_override_ignores_target(run_build, args):
    invocations = run_build(
        args, ENTRY="agent/memory_scan_agent.ts", OUT="friTap/custom.js",
    )
    assert invocations == [
        BRIDGE_INSTALL,
        "frida-compile agent/memory_scan_agent.ts -o friTap/custom.js",
    ]


@pytest.mark.parametrize("env,expected_compile", [
    ({"ENTRY": "agent/memory_scan_agent.ts"},
     "frida-compile agent/memory_scan_agent.ts -o friTap/fritap_agent.js"),
    ({"OUT": "friTap/custom.js"},
     "frida-compile agent/fritap_agent.ts -o friTap/custom.js"),
])
def test_single_override_with_ebpf_target_builds_frida(run_build, env, expected_compile):
    assert run_build(["ebpf"], **env) == [BRIDGE_INSTALL, expected_compile]
