#!/usr/bin/env bash
#
# publish_public.sh — regenerate the scrubbed PUBLIC snapshot (friTap tiering §E).
#
# Git cannot push a SUBSET of a commit, so the public tree is a regenerated
# snapshot: take the publishable set (git-tracked + non-ignored), strip every
# private.txt path, scrub the substantive Signal-E2E reveals, run the leak guard,
# then commit-tree that tree onto a local `public-main` branch. The maintainer
# pushes `public-main -> github:main` separately (today github push = DISABLE).
#
# The committed friTap/fritap_agent.js is already the PUBLIC (Signal-free) bundle
# and CI (agent-build-check) enforces it is byte-identical to a public-entry
# rebuild, so we copy it as-is — no npm in the publish path. The gitignored full
# bundle is never in the publishable set.
#
# Usage:
#   scripts/publish_public.sh --dry-run                    # strip+scrub+gates only; NO git writes
#   scripts/publish_public.sh [-m "<msg>"] [--no-release]  # the above, THEN commit-tree -> public-main
#     -m "<msg>"     commit message for the public snapshot (default: a neutral line;
#                    the public commit message must NOT name the private tier).
#     --no-release   keep friTap/about.py at the currently-published version so the
#                    push does NOT change it and publish.yml does NOT upload to PyPI
#                    (a pure code-mirror publish; release deliberately later with a
#                    version bump). Omit to carry the dev version and let it release.
#   Prints the push command; never auto-pushes.
#
# I (the build assistant) only ever run --dry-run; the git-writing path is the
# maintainer's.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PRIVATE_TXT="$REPO_ROOT/private.txt"

DRY_RUN=0
STATUS_ONLY=0
NO_RELEASE=0
PUBLIC_MSG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)    DRY_RUN=1; shift ;;
    --status)     STATUS_ONLY=1; DRY_RUN=1; shift ;;   # fast preview: skip gates, full file list, no writes
    --no-release) NO_RELEASE=1; shift ;;
    -m|--message) PUBLIC_MSG="${2:?-m needs a commit message}"; shift 2 ;;
    *) echo "usage: publish_public.sh [--dry-run|--status] [-m \"<commit message>\"] [--no-release]" >&2; exit 2 ;;
  esac
done

TMP="$(mktemp -d)"
TREE="$TMP/public_tree"
TEMP_INDEX="$TMP/index"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TREE"

echo "== §E publish ($([ "$DRY_RUN" -eq 1 ] && echo dry-run || echo FULL)) =="

# --- 1. publishable set (tracked + non-ignored), into the throwaway tree -------
( cd "$REPO_ROOT" && git ls-files --cached --others --exclude-standard -z ) \
  | rsync -a --files-from=- --from0 "$REPO_ROOT/" "$TREE/"

# --- 2. strip private.txt paths ------------------------------------------------
shopt -s nullglob
while IFS= read -r raw || [ -n "$raw" ]; do
  line="${raw%%#*}"; line="${line#"${line%%[![:space:]]*}"}"; line="${line%"${line##*[![:space:]]}"}"
  [ -z "$line" ] && continue
  for m in $TREE/$line; do rm -rf "$m"; done
done < "$PRIVATE_TXT"
shopt -u nullglob
echo "  stripped private.txt paths"

# --- 3. scrub substantive reveals (setup.py extra, mkdocs nav, CHANGELOG) ------
python3 "$SCRIPT_DIR/scrub_public_tree.py" "$TREE"

# Snapshot the INTENDED publish set NOW — a clean tree, before the gates below
# create any __pycache__/.git scratch. The completeness guard (step 4.9) checks
# the committed snapshot against this list, so a tracked file silently dropped by
# .gitignore can never again be deleted from the public repo unnoticed.
( cd "$TREE" && find . -type f | sed 's#^\./##' | LC_ALL=C sort ) > "$TMP/expected.txt"

# Gates 4 / 4.5 / 4.6 below (leak guard, mkdocs --strict, pytest) are the slow
# checks. --status skips them for a fast file-level preview (still zero writes);
# --dry-run and the real publish always run them.
if [ "$STATUS_ONLY" -ne 1 ]; then
# --- 4. leak guard (HARD rules must pass; exit 2 = accepted residuals) ---------
echo "  running leak guard on the scrubbed tree…"
set +e
bash "$SCRIPT_DIR/check_public_denylist.sh" "$TREE"
guard_rc=$?
set -e
case "$guard_rc" in
  0) echo "  leak guard: clean (publish-ready)";;
  2) echo "  leak guard: PASS-structural — accepted bare-'signal' residuals remain (operational-privacy stance; HARD rules are the contract — §F-strict). Continuing.";;
  *) echo "ERROR: leak guard HARD failure (rc=$guard_rc) — refusing to publish." >&2; exit 1;;
esac

# --- 4.5 docs: the SCRUBBED tree must still build clean (§G) --------------------
# CI's mkdocs --strict runs on the FULL tree (which still has signal.md); it never
# sees this scrubbed tree. So verify HERE that stripping signal.md + scrubbing the
# @scrub:signal-e2e regions left no dangling page/nav/link. Guarded: skip with a
# warning if mkdocs is absent (minimal publish env) — present means it must pass.
if command -v mkdocs >/dev/null 2>&1; then
  echo "  building scrubbed docs (mkdocs --strict)…"
  # The git-revision-date mkdocs plugin needs the docs inside a git repo; the
  # throwaway tree isn't one. Give it a disposable repo so the build matches CI,
  # then drop the .git before commit-tree (step 5) walks $TREE.
  ( cd "$TREE" && git init -q && git add -A \
      && git -c user.email=publish@local -c user.name=publish commit -q -m snapshot ) >/dev/null 2>&1 || true
  docs_ok=1
  ( cd "$TREE" && mkdocs build --clean --strict --site-dir "$TMP/site_check" ) >"$TMP/mkdocs.log" 2>&1 || docs_ok=0
  rm -rf "$TREE/.git" "$TREE/site" "$TMP/site_check"
  if [ "$docs_ok" -eq 1 ]; then
    echo "  mkdocs --strict: clean"
  else
    echo "ERROR: mkdocs --strict failed on the scrubbed tree — refusing to publish." >&2
    tail -25 "$TMP/mkdocs.log" >&2
    exit 1
  fi
else
  echo "  WARNING: mkdocs not installed — skipping scrubbed-tree docs check (install docs deps to enforce)."
fi

# --- 4.6 tests: the public test suite must pass on the SCRUBBED tree (§F-strict) -
# CI runs pytest on the FULL tree (signal present); it never sees this stripped
# tree, where `signal` is not a registered protocol. Signal-coupled public tests
# skip cleanly when signal is stripped — verify nothing actually FAILS here, so a
# published tree never ships a red suite. cd into the tree so the editable full-repo
# install can't shadow it. Guarded: skip with a warning if pytest is absent.
if python3 -m pytest --version >/dev/null 2>&1; then
  echo "  running public test suite on the scrubbed tree (pytest)…"
  tests_ok=1
  ( cd "$TREE" && python3 -m pytest tests/unit -q -p no:cacheprovider ) >"$TMP/pytest.log" 2>&1 || tests_ok=0
  if [ "$tests_ok" -eq 1 ]; then
    echo "  pytest: clean (signal-coupled tests skipped)"
  else
    echo "ERROR: pytest failed on the scrubbed tree — refusing to publish." >&2
    tail -30 "$TMP/pytest.log" >&2
    exit 1
  fi
else
  echo "  WARNING: pytest not installed — skipping scrubbed-tree test gate (install dev deps to enforce)."
fi
fi   # end slow gates (skipped by --status)

# --- 4.7 optional: keep friTap/about.py at the published version (--no-release) -
# publish.yml (on GitHub) uploads to PyPI when friTap/about.py's __version__
# changes on main. For a pure CODE-mirror publish, restore about.py from the
# current public head so the snapshot's version equals the parent's → the push
# never changes about.py and publish.yml never triggers. Done AFTER the gates so
# they still validate the real (dev) version. Omit --no-release to carry the dev
# version and let publish.yml release it deliberately.
if [ "$NO_RELEASE" -eq 1 ]; then
  if git -C "$REPO_ROOT" cat-file -e refs/remotes/github/main:friTap/about.py 2>/dev/null; then
    git -C "$REPO_ROOT" show refs/remotes/github/main:friTap/about.py > "$TREE/friTap/about.py"
    echo "  --no-release: friTap/about.py frozen at the published version (no PyPI trigger)"
  else
    echo "  WARNING: --no-release set but refs/remotes/github/main:friTap/about.py absent" >&2
    echo "           — run 'git fetch github' first; carrying the dev version for now." >&2
  fi
fi

# --- 4.8 build the snapshot tree (TEMP index; real index/HEAD/branch untouched) -
# git add -A WITHOUT -f: the .gitignore public-mirror allowlist makes the tracked
# files stageable while scratch (__pycache__, etc.) stays excluded.
GIT_INDEX_FILE="$TEMP_INDEX" git -C "$REPO_ROOT" --work-tree="$TREE" add -A
TREE_SHA="$(GIT_INDEX_FILE="$TEMP_INDEX" git -C "$REPO_ROOT" write-tree)"
# Parent = previous public snapshot, else the EXISTING github/main, so the first
# publish is a fast-forward CHILD (never a history-destroying force). A rootless
# orphan is only for a brand-new EMPTY public repo (explicit FRITAP_PUBLIC_ORPHAN).
PREV="$(git -C "$REPO_ROOT" rev-parse -q --verify refs/heads/public-main \
        || git -C "$REPO_ROOT" rev-parse -q --verify refs/remotes/github/main \
        || true)"

# --- 4.9 completeness guard: snapshot MUST contain every intended file ---------
# Catches a tracked file silently dropped by .gitignore — the failure mode that
# would otherwise DELETE files from the public repo on push.
git -C "$REPO_ROOT" ls-tree -r --name-only "$TREE_SHA" | LC_ALL=C sort > "$TMP/actual.txt"
MISSING="$(comm -23 "$TMP/expected.txt" "$TMP/actual.txt")"
if [ -n "$MISSING" ]; then
  echo "ERROR: the snapshot is MISSING tracked files from the public tree —" >&2
  echo "       publishing would DELETE them from github:main. Add a '!negation' in" >&2
  echo "       .gitignore for each (public-mirror allowlist block), then re-run:" >&2
  echo "$MISSING" | sed 's/^/         /' >&2
  exit 1
fi

# --- 4.10 publish preview: what 'public-main -> main' would change -------------
echo "  === publish preview (snapshot vs $( [ -n "$PREV" ] && git -C "$REPO_ROOT" rev-parse --short "$PREV" || echo "EMPTY repo" )) ==="
if [ -n "$PREV" ]; then
  git -C "$REPO_ROOT" diff --name-status "$PREV" "$TREE_SHA" > "$TMP/preview.txt" || true
  awk '{c[substr($1,1,1)]++} END{printf "    +%d added   ~%d modified   -%d deleted   »%d renamed   (%d files total)\n", c["A"], c["M"], c["D"], c["R"], NR}' "$TMP/preview.txt"
  if [ "$STATUS_ONLY" -eq 1 ]; then
    echo "    --- changed files (A added · M modified · D deleted · R renamed) ---"
    LC_ALL=C sort "$TMP/preview.txt" | sed 's/^/      /'
  elif grep -q '^D' "$TMP/preview.txt"; then
    echo "    ⚠ DELETIONS — these files would be REMOVED from github:main (review!):"
    grep '^D' "$TMP/preview.txt" | sed 's/^D[[:space:]]*/        - /'
  fi
else
  echo "    first publish to an empty repo — all $(wc -l < "$TMP/actual.txt" | tr -d ' ') files added"
fi

if [ "$DRY_RUN" -eq 1 ]; then
  if [ "$STATUS_ONLY" -eq 1 ]; then
    echo "== status preview: $(wc -l < "$TMP/actual.txt" | tr -d ' ') files in the snapshot. Gates skipped, nothing written. (Use 'make publish-public-dry' for full validation.) =="
  else
    echo "== dry-run complete: snapshot built + verified ($(wc -l < "$TMP/actual.txt" | tr -d ' ') files). No commit/ref/branch written. =="
  fi
  exit 0
fi

# --- 5. commit-tree the verified snapshot onto local public-main (maintainer) ---
SRC_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)"
# Default is intentionally neutral — a public commit message must NOT name the
# private tier. Pass -m "<message>" for a real release.
MSG="${PUBLIC_MSG:-Public snapshot from $SRC_SHA}"
if [ -n "$PREV" ]; then
  COMMIT_SHA="$(git -C "$REPO_ROOT" commit-tree "$TREE_SHA" -p "$PREV" -m "$MSG")"
  echo "  snapshot parent: $PREV (push to github:main fast-forwards — no history loss)"
elif [ "${FRITAP_PUBLIC_ORPHAN:-0}" = "1" ]; then
  echo "  FRITAP_PUBLIC_ORPHAN=1: creating a ROOTLESS public-main (brand-new public repo only)"
  COMMIT_SHA="$(git -C "$REPO_ROOT" commit-tree "$TREE_SHA" -m "$MSG")"
else
  echo "ERROR: no local public-main and no github/main to parent onto." >&2
  echo "       Refusing to create a rootless orphan — pushing it onto an existing" >&2
  echo "       github:main would require a history-destroying --force. Fix:" >&2
  echo "         git fetch github      # populate refs/remotes/github/main, then re-run" >&2
  echo "       or, for a genuinely EMPTY new public repo: re-run with FRITAP_PUBLIC_ORPHAN=1." >&2
  exit 1
fi
git -C "$REPO_ROOT" update-ref refs/heads/public-main "$COMMIT_SHA"
echo "== public-main updated to $COMMIT_SHA =="
echo "   message: $MSG"
[ "$NO_RELEASE" -eq 1 ] && echo "   (--no-release: about.py frozen → this publish will NOT release to PyPI)"
echo "   Next (maintainer): push ONLY public-main -> main via the explicit URL"
echo "   (leaves the remote's DISABLE pushurl intact; the pre-push hook permits this pair):"
echo "     git push git@github.com:fkie-cad/friTap.git public-main:main"
