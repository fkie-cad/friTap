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

## Agent ABI (`AGENT_ABI_VERSION`)

`friTap/constants.py:AGENT_ABI_VERSION` versions the JS↔Python boundary:
`config_batch` fields, `ContentType` values, and `rpc.exports`. **Bump it
whenever that boundary changes**, and in the same commit:

1. `python dev/generate_agent_types.py` — mirrors the constant into
   `agent/shared/generated_constants.ts`.
2. `./dev/compile_agent.sh` — bakes it into `friTap/fritap_agent.js`. Confirm
   the `done. Agent: <bytes>` line: it is the only positive signal. The script
   writes `frida-compile -o` straight onto the bundle with no temp file or
   backup, so after a failed build what is on disk is undefined (previous bundle
   or partial write) and a later test would not be exercising your change.
3. Commit both regenerated artifacts.

`tests/unit/test_agent_bundle_abi_static.py` fails if any of the three
(constant, generated TS, shipped bundle) disagree, which is what stops
"bumped the constant, forgot to rebuild" from shipping.

### Private / extended bundles move in lockstep

A package contributing a `fritap.agent_bundle` entry point must declare the
**same** `AGENT_ABI_VERSION` as the friTap it is installed alongside. If it does
not, friTap logs a warning and falls back to the bundled agent — the private
hooks simply do not load. Release such packages together with any ABI bump, and
mention the required ABI in their release notes.

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

## Pinned dependencies (revert when upstream releases)

- **`frida-java-bridge` → upstream `main` git commit** (currently
  `git+https://github.com/frida/frida-java-bridge.git#b38a5b64…` in
  `package.json`). The published `7.0.13` predates
  [#398](https://github.com/frida/frida-java-bridge/pull/398), which fixes the
  Android 17 / API 37 ART crash (`Unable to find copied methods in
  java/lang/Thread`); the pin also carries
  [#399](https://github.com/frida/frida-java-bridge/pull/399) (ARM32). The HTTPS
  `resolved` URL in `package-lock.json` is intentional — npm canonicalizes
  GitHub deps to `git+ssh://`, which fails keyless clones on CI runners; if you
  re-run `npm install` and it rewrites `resolved` back to `git+ssh://`, restore
  the `git+https://` form before committing.
  - **Trigger to act:** when frida-java-bridge publishes a release `> 7.0.13`
    that contains #398, revert `package.json` to a semver pin (e.g. `^7.0.14`),
    run `npm install && ./dev/compile_agent.sh`, re-verify on API 37, and remove
    this entry plus the temporary note in `CONTRIBUTING.md`.

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
- UI facade `friTap.ui` — the embedding seam for host projects, a separate
  namespace from `friTap.__all__` and lazy (importing it loads neither
  textual nor frida nor capture code). Its `__all__`: `AppCipherDecoder`,
  `BaseAnalyzer`, `BodyDecoderSpec`, `DecodedView`, `DetailTabSpec`,
  `ExtensionLoadError`, `Finding`, `FlowColumnSpec`, `LayerFieldSpec`,
  `ReplayController`, `Severity`,
  `TapSource`, `TapViewerApp`, `TapViewerScreen`,
  `UI_EXTENSION_ENTRY_POINT_GROUP`, `available_analyzers`,
  `extension_load_errors`, `get_body_decoders`,
  `get_detail_tabs`, `get_filter_fields`, `get_flow_columns`, `install_theme`,
  `iter_replay_rows`, `load_extensions`, `open_tap`, `register_analyzer`,
  `register_app_cipher_decoder`, `register_body_decoder`,
  `register_detail_tab`, `register_filter_field`, `register_flow_column`,
  `theme_variable_defaults`. Extension entry-point group:
  `fritap.ui_extensions`. `friTap.tui.*` stays internal. Embedding guide:
  [docs/api/embedding.md](docs/api/embedding.md).
  - **Stable** within `friTap.ui`: `open_tap`, `TapViewerApp`,
    `TapViewerScreen` (incl. `TapViewerScreen.Closed` and `go_back`),
    `install_theme`, `register_analyzer`, `available_analyzers`,
    `register_app_cipher_decoder`, `AppCipherDecoder`, `DecodedView`,
    `ReplayController`, `BaseAnalyzer`, `Finding`, `Severity`.
  - **PROVISIONAL** (owner-approved; may change in a MINOR release until the
    extension API has settled (the viewer widgets already consume the
    getters); mirrored by `friTap.ui.PROVISIONAL`):
    `TapSource`, `DetailTabSpec`, `FlowColumnSpec`, `BodyDecoderSpec`,
    `LayerFieldSpec`, `register_detail_tab`, `register_flow_column`,
    `register_body_decoder`, `register_filter_field`, `get_detail_tabs`,
    `get_flow_columns`, `get_body_decoders`, `get_filter_fields`,
    `load_extensions`, `UI_EXTENSION_ENTRY_POINT_GROUP`, `ExtensionLoadError`,
    `extension_load_errors`, `iter_replay_rows`, `theme_variable_defaults`.
  - `AppCipherDecoder` / `DecodedView` are a carve-out from the internal
    `friTap.parsers.*` namespace (like `ParseResult`): these two symbols are
    covered, the rest of `friTap.parsers.app_ciphers` is not.
  - `BaseAnalyzer`, `Finding`, `Severity` and `ReplayController` in
    `friTap.ui` are aliases of the stable root-package names (the same
    objects as `friTap.BaseAnalyzer` etc.).
  - The extension registry lives in core (`friTap.extensions`; re-exported
    by `friTap.ui` and `friTap.ui.extensions`) so core code never imports
    the UI. Core must not import `friTap.ui` / `friTap.tui` (layering rule
    R14) — the UI is planned to ship as its own distribution.
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
