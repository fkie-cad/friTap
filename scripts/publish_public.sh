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
NO_RELEASE=0
PUBLIC_MSG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)    DRY_RUN=1; shift ;;
    --no-release) NO_RELEASE=1; shift ;;
    -m|--message) PUBLIC_MSG="${2:?-m needs a commit message}"; shift 2 ;;
    *) echo "usage: publish_public.sh [--dry-run] [-m \"<commit message>\"] [--no-release]" >&2; exit 2 ;;
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

if [ "$DRY_RUN" -eq 1 ]; then
  echo "== dry-run complete: scrubbed tree validated. No git objects/refs written. =="
  echo "   (scrubbed tree was at $TREE — removed on exit)"
  exit 0
fi

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

# --- 5. commit-tree the scrubbed tree onto local public-main (maintainer path) --
# Uses a TEMP index so the working index/HEAD/checked-out branch are untouched.
SRC_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)"
GIT_INDEX_FILE="$TEMP_INDEX" git -C "$REPO_ROOT" --work-tree="$TREE" add -A
TREE_SHA="$(GIT_INDEX_FILE="$TEMP_INDEX" git -C "$REPO_ROOT" write-tree)"
# Parent = the previous public snapshot if we have one, else the EXISTING public
# github/main — so the very FIRST publish is a normal CHILD of the live public
# history and the push fast-forwards (preserving every existing commit/tag/branch,
# never a history-destroying --force). A true rootless orphan is correct ONLY for
# a brand-new EMPTY public repo and must be an explicit opt-in, never the silent
# default (silently orphaning here is the force-push footgun).
PREV="$(git -C "$REPO_ROOT" rev-parse -q --verify refs/heads/public-main \
        || git -C "$REPO_ROOT" rev-parse -q --verify refs/remotes/github/main \
        || true)"
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
