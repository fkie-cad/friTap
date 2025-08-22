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

# Runtime requirements
install_requires = [
    "frida>=16.0.0",
    "frida-tools>=11.0.0",
    "AndroidFridaManager",
    "hexdump",
    "scapy",
    "watchdog",
    "click",
    'importlib-resources; python_version < "3.9"',
    "psutil",
    "rich>=13.0.0",
]

setup(
    name="friTap",
    version=about.__version__,
    description=(
        "Simplifies SSL/TLS traffic analysis and key extraction using Frida "
        "across major platforms."
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",

    url="https://github.com/fkie-cad/friTap",
    author=about.__author__,
    author_email="daniel.baier@fkie.fraunhofer.de",
    license="GPL-3.0-only",  # or "GPL-3.0-or-later" to match your LICENSE

    packages=find_packages(exclude=("create_legacy_agent", "create_standalone_release")),
    python_requires=">=3.8",
    install_requires=install_requires,

    # Include non-Python assets inside the package
    package_data={
        "friTap": [
            "_ssl_log.js",
            "_ssl_log_legacy.js",
            "assets/tcpdump_binaries/*",
        ]
    },
    include_package_data=True,

    classifiers=[
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Natural Language :: English",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: JavaScript",
        "Topic :: Security",
        "Topic :: Software Development :: Debuggers",
    ],
    keywords=["mobile", "instrumentation", "frida", "hook", "SSL decryption"],

    entry_points={
        "console_scripts": [
            "fritap=friTap.friTap:main",
        ],
    },
    project_urls={
        "Source": "https://github.com/fkie-cad/friTap",
        "Issues": "https://github.com/fkie-cad/friTap/issues",
        "Documentation": "https://fkie-cad.github.io/friTap/",
    },
)