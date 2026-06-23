#!/usr/bin/env bash
#
# verify_public_build.sh
#
# Verification harness for friTap's public/private tiering.
#
# Purpose:
#   Simulate the PUBLIC build of friTap (the full source tree minus the paths
#   listed in private.txt) and verify that the resulting stripped tree is both
#   import-clean (the public package still imports and exposes the expected
#   public surface) and leak-clean (no private files survive and no private
#   reveal-tokens appear anywhere in the tree).
#
# Safety:
#   This script NEVER mutates the real repository. All stripping and checking
#   happens on a throwaway copy inside a temp dir, which is removed on exit.
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Resolve REPO_ROOT robustly from this script's own location.
# The repo root is the parent dir of the directory containing this script.
# ---------------------------------------------------------------------------
SCRIPT_SOURCE="${BASH_SOURCE[0]}"
# Resolve any symlinks so SCRIPT_DIR points at the real on-disk location.
while [ -h "$SCRIPT_SOURCE" ]; do
  dir="$(cd -P "$(dirname "$SCRIPT_SOURCE")" >/dev/null 2>&1 && pwd)"
  SCRIPT_SOURCE="$(readlink "$SCRIPT_SOURCE")"
  # Handle relative symlink targets.
  [[ "$SCRIPT_SOURCE" != /* ]] && SCRIPT_SOURCE="$dir/$SCRIPT_SOURCE"
done
SCRIPT_DIR="$(cd -P "$(dirname "$SCRIPT_SOURCE")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd -P "$SCRIPT_DIR/.." >/dev/null 2>&1 && pwd)"

# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"

PRIVATE_TXT="$REPO_ROOT/private.txt"
PRIVATE_TERMS="$REPO_ROOT/scripts/private_terms.txt"

echo "=== friTap public-build verification ==="
echo "REPO_ROOT:     $REPO_ROOT"
echo "private.txt:   $PRIVATE_TXT"
echo "private_terms: $PRIVATE_TERMS"
echo

# Accumulated failure count. Skips do NOT increment this.
FAILURES=0

fail() {
  echo "FAIL: $*"
  FAILURES=$((FAILURES + 1))
}

pass() {
  echo "PASS: $*"
}

# ---------------------------------------------------------------------------
# Sanity: the inputs we depend on must exist in the real repo.
# ---------------------------------------------------------------------------
if [ ! -f "$PRIVATE_TXT" ]; then
  echo "ERROR: private.txt not found at $PRIVATE_TXT" >&2
  exit 2
fi
if [ ! -f "$PRIVATE_TERMS" ]; then
  echo "ERROR: scripts/private_terms.txt not found at $PRIVATE_TERMS" >&2
  exit 2
fi

# ---------------------------------------------------------------------------
# Step 1: temp dir + trap cleanup.
# ---------------------------------------------------------------------------
TMP="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP"
}
trap cleanup EXIT

PUBLIC_TREE="$TMP/public_tree"

# ---------------------------------------------------------------------------
# Step 2: copy the repo into $TMP/public_tree, excluding regenerable/irrelevant
# directories and artifacts. Trailing slash on the source keeps the contents at
# the destination root.
# ---------------------------------------------------------------------------
echo "--- Step 2: copying repo into throwaway public tree ---"
# Mirror the authoritative §E publish: only files that WOULD be committed are
# published. `git ls-files --cached --others --exclude-standard` = tracked files
# PLUS new files that aren't gitignored — which auto-excludes every gitignored
# runtime artifact (debug logs, captured pcaps, generated site/, *.egg-info,
# .pytest_cache, research scratch dirs, *.fritap.json, __pycache__) without us
# enumerating them, while still including not-yet-committed source under review.
mkdir -p "$PUBLIC_TREE"
fritap_assemble_public_tree "$REPO_ROOT" "$PUBLIC_TREE"
echo "Copied to: $PUBLIC_TREE"
echo

# ---------------------------------------------------------------------------
# Step 3: strip private paths listed in private.txt.
#
#   - Skip blank lines and comment lines (first non-space char is '#').
#   - Strip inline trailing '# ...' comments and surrounding whitespace.
#   - Treat a trailing slash as a directory.
#   - Patterns may contain '*' globs (e.g. tests/unit/test_signal_*.py).
#   - Matching nothing is NOT an error (forward-looking entries may be absent).
# ---------------------------------------------------------------------------
echo "--- Step 3: stripping private paths ---"
# Verbose: report "(no match)" / "removed <relpath>" per private.txt entry.
fritap_strip_private_paths "$PUBLIC_TREE" "$PRIVATE_TXT" verbose
echo

# ---------------------------------------------------------------------------
# Step 4: LEAK CHECKS on the stripped tree.
# ---------------------------------------------------------------------------
echo "--- Step 4a: assert private paths no longer exist ---"
MUST_BE_GONE=(
  "agent/signal"
  "friTap/offline/signal"
  "friTap/protocols/signal_handler.py"
  "friTap/flow/signal_live.py"
  "docs/protocols/signal.md"
  "scripts/private_terms.txt"
)
for rel in "${MUST_BE_GONE[@]}"; do
  if [ -e "$PUBLIC_TREE/$rel" ]; then
    fail "private path still present in public tree: $rel"
  else
    pass "absent: $rel"
  fi
done
echo

echo "--- Step 4b: token scan for private reveal-tokens ---"
# IMPORTANT: read the pattern file from the REAL repo (REPO_ROOT), because
# scripts/private_terms.txt is itself stripped out of the public tree in step 3.
#
# private_terms.txt carries '#' comments and blank lines (and some comment lines
# contain an unbalanced ')' which is an INVALID ERE) -- feeding those to
# `grep -f` errors out (exit 2). So build a clean pattern list first: drop blank
# lines and comment lines, keeping only the actual reveal-token patterns.
CLEAN_TERMS="$TMP/clean_terms.txt"
sed -e 's/^[[:space:]]*//' "$PRIVATE_TERMS" | grep -vE '^(#|$)' > "$CLEAN_TERMS" || true

# grep exit codes: 0 = matches found (=> leak => FAIL), 1 = no matches (=> PASS),
# >1 = a real error. -I skips binary files (pcaps etc.); also exclude capture
# artifacts explicitly.
set +e
TOKEN_HITS="$(grep -rniE -I \
  --exclude-dir='.git' \
  --exclude-dir='__pycache__' \
  --exclude='*.pcapng' --exclude='*.pcap' --exclude='*.tap' \
  -f "$CLEAN_TERMS" \
  "$PUBLIC_TREE" 2>/dev/null)"
grep_status=$?
set -e

case "$grep_status" in
  0)
    fail "private reveal-token(s) found in public tree:"
    # Print hits as file:line, with paths relative to the public tree.
    while IFS= read -r hit; do
      [ -z "$hit" ] && continue
      echo "      ${hit#"$PUBLIC_TREE/"}"
    done <<< "$TOKEN_HITS"
    ;;
  1)
    pass "no private reveal-tokens found"
    ;;
  *)
    echo "ERROR: grep failed during token scan (exit $grep_status)" >&2
    exit 2
    ;;
esac
echo

# ---------------------------------------------------------------------------
# Step 5: IMPORT CHECKS.
#
# Only run if python3 exists AND friTap can be imported from the public tree
# (i.e. dependencies are installed in the active environment). If friTap cannot
# even be imported, that means deps are missing in this env -> SKIP (not a fail).
# ---------------------------------------------------------------------------
echo "--- Step 5: import checks ---"

run_import_checks=true
if ! command -v python3 >/dev/null 2>&1; then
  echo "SKIP import checks: python3 not available"
  run_import_checks=false
else
  # Probe import of friTap from within the public tree.
  if ! ( cd "$PUBLIC_TREE" && python3 -c "import friTap" >/dev/null 2>&1 ); then
    echo "SKIP import checks: friTap deps not installed in this env"
    run_import_checks=false
  fi
fi

# Helper: run one python check from inside the public tree.
# Usage: py_check "<description>" "<python source>"
py_check() {
  local desc="$1"
  local src="$2"
  local out
  set +e
  out="$( cd "$PUBLIC_TREE" && python3 -c "$src" 2>&1 )"
  local status=$?
  set -e
  if [ "$status" -eq 0 ]; then
    pass "$desc"
    # Echo the python's own success line(s), indented.
    if [ -n "$out" ]; then
      while IFS= read -r ln; do
        echo "      $ln"
      done <<< "$out"
    fi
  else
    fail "$desc"
    # Surface the captured traceback so the developer can act on it.
    while IFS= read -r ln; do
      echo "      $ln"
    done <<< "$out"
  fi
}

if [ "$run_import_checks" = true ]; then
  # Registry must no longer advertise the 'signal' protocol.
  # NOTE: available_protocol_names may be absent on older code; if the import
  # or attribute access fails, py_check captures the traceback and marks FAIL,
  # signalling that the expected registry change isn't in place.
  py_check "protocols registry excludes 'signal'" \
"from friTap.protocols import registry
names = registry.available_protocol_names()
assert 'signal' not in names, names
print('OK protocols:', names)"

  py_check "import friTap.flow.layer_registry" \
"import friTap.flow.layer_registry
print('OK layer_registry import')"

  py_check "import friTap.offline.pcap_to_tap" \
"import friTap.offline.pcap_to_tap
print('OK pcap_to_tap import')"

  py_check "import friTap.message_router" \
"import friTap.message_router
print('OK message_router import')"

  py_check "import friTap.constants" \
"import friTap.constants
print('OK constants import')"
fi
echo

# ---------------------------------------------------------------------------
# Step 6: final summary + exit code.
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Total failures: $FAILURES"
if [ "$FAILURES" -gt 0 ]; then
  echo "RESULT: FAIL"
  exit 1
fi
echo "RESULT: PASS"
exit 0
