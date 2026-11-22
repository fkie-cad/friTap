# friTap Development Tools

This directory contains development scripts, build tools, and CI support files for friTap.

## Prerequisites

- **Python 3.10+**
- **Node.js 16+**
- **Git**

## Build from Source

```bash
# 1. Clone the repository
git clone https://github.com/fkie-cad/friTap.git
cd friTap

# 2. Create and activate a virtual environment
python -m venv env
source env/bin/activate    # Linux/macOS
# env\Scripts\activate     # Windows

# 3. Install Python dependencies
pip install -e .[dev]

# 4. Install frida-tools (provides frida-compile) and Frida module dependencies
pip install frida-tools
frida-pm install frida-objc-bridge frida-java-bridge

# 5. Compile the TypeScript agent
frida-compile agent/fritap_agent.ts -o friTap/fritap_agent.js
# or: ./dev/compile_agent.sh    (Linux/macOS)
# or: dev\compile_agent.bat     (Windows)

# 6. Run the test suite
python dev/run_tests.py all

# 7. Regenerate TypeScript schema types (after modifying Pydantic models)
python dev/generate_agent_types.py

# 8. Docker build (optional)
docker build -f dev/Dockerfile .
```

## Scripts

| Script | Purpose |
|---|---|
| `compile_agent.sh` / `compile_agent.bat` | Compile the TypeScript agent to JavaScript |
| `generate_agent_types.py` | Generate `agent/schemas/messages.ts` from Pydantic models |
| `derive_boringssl_keylog_offset.py` | Derive the Apple BoringSSL `SSL_CTX.keylog_callback` offset from iOS Simulator runtimes |
| `run_tests.py` | Unified test runner (unit, integration, agent, coverage) |
| `macos_verify/verify.sh` | End-to-end capture verification on macOS against a local TLS rig (see below) |
| `fizz/` (local only, gitignored) | Maintainer-local tooling (`genfix.py`) that regenerates `agent/shared/__fixtures__/fizz_meta_arm64.ts` from pulled Facebook/Instagram libraries; not shipped with the repository |
| `setup_dev.py` | Automated dev environment setup |
| `entrypoint.sh` | Docker container entrypoint |
| `Dockerfile` | Docker image for agent compilation |

## End-to-end verification on macOS

`dev/macos_verify/` is a device-free rig that drives friTap against a local
HTTPS server and a CFNetwork/BoringSSL client, then asserts on the captured
keys. It is the practical stand-in for a jailbroken iOS device: iOS and macOS
share `/usr/lib/libboringssl.dylib` and the same `SSL_CTX` layout, so the
offset derivation, the spawn-mode bootstrap path, and every host-side bug
behind fkie-cad/friTap#65 reproduce there.

```bash
./dev/macos_verify/verify.sh --list    # what it checks
./dev/macos_verify/verify.sh           # run it (exits non-zero on any failure)
```

See `dev/macos_verify/README.md` for what each check proves and the two traps
worth knowing (the pre-compiled agent bundle, and never piping friTap's stdout
into `head`).

## BoringSSL keylog offset (iOS / macOS)

Apple does not export `SSL_CTX_set_keylog_callback`, so friTap hooks the exported
`SSL_CTX_set_info_callback` and writes its keylog callback **directly into the
`SSL_CTX` heap struct** at a version-dependent offset. That table lives in
`agent/legacy/tls/shared/apple_keylog_offset.ts` — a wrong value clobbers a
neighbouring field and kills the target process (fkie-cad/friTap#65).

`derive_boringssl_keylog_offset.py` recovers the ground truth statically, with no
device: iOS Simulator runtimes ship `/usr/lib/libboringssl.dylib` as a standalone
Mach-O, and `SSL_CTX_set_keylog_callback` is a local symbol whose entire body is
`str x1, [x0, #OFFSET]` + `ret`. The script reads that offset out of every installed
runtime with `nm`/`otool`.

```bash
# Print the offset of every installed iOS simulator runtime
python dev/derive_boringssl_keylog_offset.py

# Machine-readable output (runtimes, per-major grouping, parsed offset tables)
python dev/derive_boringssl_keylog_offset.py --json

# Compare the derived ground truth against the checked-in tables; exits 1 on drift
python dev/derive_boringssl_keylog_offset.py --check
```

`--check` fails when a table would write a different offset than Apple's binary
actually uses, when the iOS and macOS tables disagree for the same release era
(macOS 14 Sonoma ↔ iOS 17, macOS 15 Sequoia ↔ iOS 18, 26 ↔ 26), or when a bucket is
capped at a hardcoded version ceiling instead of staying open-ended. Run it after
touching the offset table, and whenever a new major iOS release ships.

macOS-only, and it **skips with exit 0** (never fails) when run off macOS, without
Xcode, or with no runtimes installed — so it is safe in CI. The matching pytest
module is `tests/unit/test_boringssl_keylog_offset.py`; its structural assertions run
everywhere, its derived assertions skip unless simulator runtimes are present.

Install additional runtimes to widen coverage:

```bash
xcodebuild -downloadPlatform iOS -buildVersion 16.4
xcrun simctl list runtimes            # verify what is installed
```
