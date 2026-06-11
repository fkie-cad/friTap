# Releasing friTap

## Versioning policy

friTap follows 3-segment SemVer (`MAJOR.MINOR.PATCH`).

**Rule.** When the required frida major version bumps, friTap MAJOR bumps in
the same commit. The `frida>=N.x.y,<(N+1).0.0` constraint in
`requirements.txt`, the `__version__` major in `friTap/about.py`, the
`SUPPORTED_FRIDA_MAJOR` constant in `friTap/backends/frida_backend.py`, and
the manifest in `compat.yml` move together. CI enforces this via
`dev/check_compat.py` in the `version-guard` job (`.github/workflows/ci.yml`).

**Why.** Until friTap 2.0.0 we shipped silent frida-major bumps as patch
releases (see [issue #63](https://github.com/fkie-cad/friTap/issues/63)).
The structural fix is to make the cross-file invariant un-bypassable.

## Cutting a release

1. Update `friTap/about.py` (`__version__`).
2. Update `requirements.txt` if frida major changed (must use strict-cap
   shape `frida>=N.x.y,<(N+1).0.0`).
3. Add a row to `compat.yml` if friTap major changed.
4. Update `SUPPORTED_FRIDA_MAJOR` in `friTap/backends/frida_backend.py` if
   the supported frida major changed.
5. Move `## [Unreleased]` in `CHANGELOG.md` to `## [X.Y.Z] - YYYY-MM-DD`.
6. Update version badge on `README.md` and the `version` field in
   `package.json` (kept in lockstep with `friTap/about.py`).
7. Run `npm ci && ./dev/compile_agent.sh` locally and commit the
   regenerated `friTap/fritap_agent.js` if it changed. CI's
   `agent-build-check` job will fail if the committed artifact does not
   match a fresh rebuild against the pinned toolchain.
8. If you bumped friTap MAJOR for a new frida major, add the new frida
   patch version to the `smoke-import` matrix in
   `.github/workflows/ci.yml`. Keep the previous frida version in the
   matrix for one minor cycle as a deprecation window.
9. Run `python dev/check_compat.py` locally — it must print
   `version-guard: OK (friTap N, frida M.x)`.
10. Commit on `main`. `publish.yml` fires on `friTap/about.py` changes:
    - Builds sdist + wheel.
    - Publishes to PyPI via OIDC trusted publishing
      (`id-token: write` scoped to the publish job only).
    - Auto-creates and pushes a `v<version>` tag on the merge commit
      (`contents: write` scoped to the `tag` job only; idempotent against
      `git ls-remote` so re-runs no-op cleanly).
    - Verify both jobs ran green at https://github.com/fkie-cad/friTap/actions
      and the tag appears at https://github.com/fkie-cad/friTap/tags.

## Pre-releases

Use `X.Y.Z-rc.1` / `X.Y.Z-alpha.1` for frida-major-transition testing. PyPI
hides pre-releases by default; users opt in with `pip install fritap --pre`.

## Third-party deprecation watchlist

We don't directly depend on these, but they sit on the agent-build path
through frida and may need attention if upstream stops maintaining them.

- **`prebuild-install`** (transitive: friTap → `frida` (npm) → `prebuild-install`).
  Marked deprecated by its author; npm warns on every `npm ci` run.
  `prebuild-install` is what frida uses to fetch the platform-native
  `frida_binding.node` at install time. We can't replace it ourselves.
  - **Watch:** [frida/frida-node](https://github.com/frida/frida-node)
    for migration to a maintained alternative
    (`prebuildify`, `node-gyp-build`, etc.).
  - **Trigger to act:** if `prebuild-install` ever fully breaks,
    `npm ci` fails on macOS/Linux/Windows runners and the
    `agent-build-check` CI job goes red. At that point either pin a
    frida version that still works or contribute the migration upstream.

## Public API surface

friTap declares two stability tiers:

**Stable (covered by SemVer)** — listed in `friTap/__init__.py:__all__`:

- CLI (`fritap` console script) — the *primary* contract. Flag removals or
  output-format breaks require MAJOR.
- Python: `FriTap`, `FriTapSession`, `FriTapConfig`, `DeviceConfig`,
  `OutputConfig`, `HookingConfig`, all `*Event` types, `EventBus`, `Flow`,
  `FlowChunk`, `FlowState`, `FlowEventType`, `FlowSummary`, `TapReader`,
  `TapMeta`, `Severity`, `Finding`, `BaseAnalyzer`, `analyze_tap`,
  `analyze_tap_multi`, `AnalyzerPlugin`, `severity_rank`, the protobuf
  utilities, and `__version__`.
- Offline analyze orchestration: `analyze_tap_report`, `AnalyzeReport`,
  `list_analyzers`, `list_report_formats`, `Reporter`, `JsonReporter`,
  `CsvReporter`, `MarkdownReporter`, `TableReporter`.
- Offline pcap → tap: `pcap_to_tap`, `convert_pcap_to_tap`, `ConvertResult`,
  `NoDecryptionKeysError`.
- Flow replay / high-level overview: `ReplayController`, `IFlowSource`.
- Parsed-metadata types: `ParseResult`, `ProtocolLayer`, `TlsLayer`,
  `QuicLayer`, `SshLayer`. These specific symbols are stable and re-exported
  from the package root even though their home namespaces
  (`friTap.parsers.*`, `friTap.flow.layers`) remain internal.
- `SSL_Logger` is in the stable tier *but* deprecated; scheduled for
  removal in friTap 3.0. New code should use `FriTap` or `CoreController`.

**Internal (not covered)** — importable but excluded from `__all__`:

- `CoreController`, `Session`, `SessionState`, `MessagePipeline`,
  `create_default_pipeline`, and anything under `friTap.legacy.*`,
  `friTap.parsers.*`, `friTap.sinks.*`, `friTap.backends.*`,
  `friTap.tui.*`. Pin a specific friTap version if you depend on these.

**Rule.** Removing or breaking-changing anything in the *stable* tier
requires a friTap MAJOR bump in the same commit. Adding to the stable
tier is MINOR. Bug fixes and changes to the *internal* tier are PATCH.

When promoting a symbol from internal to stable, add it to `__all__` in
`friTap/__init__.py` *and* document it in this section in the same PR.

## Frida compatibility (historical)

| friTap range          | frida required | frida-tools required | Constraints file                  |
|-----------------------|----------------|----------------------|-----------------------------------|
| 1.3.0.0 – 1.3.3.3     | 15.x           | 10.x – 11.x          | `constraints/frida15.txt`         |
| 1.3.4.0 – 1.4.3.0     | 16.x           | 12.x – 13.x          | `constraints/frida16.txt`         |
| 1.4.4.0 – 1.6.3.1     | 17.x           | 14.x                 | `constraints/frida17-legacy.txt`  |
| **2.0.0+**            | 17.x           | 14.x                 | (none — `requirements.txt`)       |

frida-tools maintains its own version line: each frida-tools major is
hard-capped to a specific frida major (10.x→14, 11.x→15.2+, 12.x→16.0.9+,
13.x→16.2.2+, 14.x→17.x). The "frida-tools required" column above shows
the actual compatible majors, NOT the floor pin found in legacy
requirements.txt files. Old wheels carrying e.g. `frida-tools>=12.0.0`
silently resolved through whichever frida-tools was newest at install
time — today that's 14.x, which rejects frida 16 and breaks the legacy
agent. The constraints files make the compatible range explicit.

If you cannot upgrade frida-server, install a friTap version matching your
frida major using the constraints file from the table above. See
`constraints/README.md` for copy-paste recipes, or run
`python dev/install_legacy.py --frida-major {15|16|17}` from a fresh clone.
