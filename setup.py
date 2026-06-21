#!/usr/bin/env python3
from pathlib import Path
import importlib.util
from setuptools import setup, find_packages

# Paths
ROOT = Path(__file__).resolve().parent
PKG = "friTap"
ABOUT = ROOT / PKG / "about.py"
README = ROOT / "README.md"

# Load metadata from about.py safely
spec = importlib.util.spec_from_file_location(f"{PKG}.about", ABOUT)
about = importlib.util.module_from_spec(spec)
spec.loader.exec_module(about)  # type: ignore[attr-defined]

# Long description
long_description = README.read_text(encoding="utf-8") if README.exists() else ""

# Runtime requirements — single source of truth is requirements.txt
install_requires = (ROOT / "requirements.txt").read_text().splitlines()

setup(
    name="friTap",
    version=about.__version__,
    description=(
        "Simplifies (SSL/TLS) traffic analysis and key extraction using Frida "
        "across major platforms."
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",

    url="https://github.com/fkie-cad/friTap",
    author=about.__author__,
    author_email="daniel.baier@fkie.fraunhofer.de",
    license="GPL-3.0-only", # GPLv3 or later (see LICENSE file)

    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=install_requires,
    # The runtime crypto backend ships in the BASE install (requirements.txt):
    # `cryptography` (the floor — transport AES-CTR + AES-IGE + AES-GCM-SIV) plus
    # the optional `TgCrypto-pyrofork` AES-IGE accelerator wherever a wheel exists.
    # No crypto extra is needed; only the dev toolchain is an extra. For a lean
    # install that skips the crypto backend, see requirements-minimal.txt.
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "pytest-mock>=3.10",
            "pytest-timeout>=2.1",
            "ruff>=0.1.0",
        ],
    },

    # Include non-Python assets inside the package
    package_data={
        "friTap": [
            "fritap_agent.js",
            "assets/tcpdump_binaries/*",
            "tui/css/*.tcss",
            "patterns/*.json",
            "plugins/shared_utility/*.js",
            "plugins/examples/README.md",
        ]
    },
    include_package_data=True,
    data_files=[
        ("integrations/wireshark", [
            "integrations/wireshark/fritap-extcap",
            "integrations/wireshark/install.sh",
        ]),
    ],

    classifiers=[
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Natural Language :: English",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: JavaScript",
        "Topic :: Security",
        "Topic :: Software Development :: Debuggers",
    ],
    keywords=["mobile", "instrumentation", "frida", "hook", "SSL decryption", "protocol decryption"],

    entry_points={
        "console_scripts": [
            "fritap=friTap.friTap:main",
        ],
        # Third-party packages can expose analyzers by declaring this group:
        #     [fritap.analyzers]
        #     my-analyzer = my_pkg.analyzers:MyAnalyzer
        # friTap ships no analyzers via entry points itself; this declares the
        # group as a known, documented discovery target.
        "fritap.analyzers": [],
        # Third-party packages can expose offline protocol decryptors here:
        #     [fritap.offline_decryptors]
        #     my-proto = my_pkg.offline_decryptors
        # The target module sets ``is_fritap_offline_decryptor = True`` and
        # defines one or more ``OfflineDecryptorEntry`` instances at module level
        # (see friTap.offline.discovery). Declared here as a documented target.
        "fritap.offline_decryptors": [],
        # Full/extended builds expose their compiled Frida agent bundle here so
        # the host auto-selects it (ABI-filtered) without FRITAP_AGENT_BUNDLE:
        #     [fritap.agent_bundle]
        #     full = my_pkg.agent_bundle
        # The target exposes ``AGENT_ABI_VERSION`` plus ``agent_bundle_path()``
        # (or ``AGENT_BUNDLE_PATH``); see SSL_Logger._discover_agent_bundle.
        # friTap ships none publicly. Generic — names no protocol.
        "fritap.agent_bundle": [],
    },
    project_urls={
        "Source": "https://github.com/fkie-cad/friTap",
        "Issues": "https://github.com/fkie-cad/friTap/issues",
        "Documentation": "https://fkie-cad.github.io/friTap/",
    },
)