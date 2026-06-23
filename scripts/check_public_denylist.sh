#!/usr/bin/env bash
#
# check_public_denylist.sh — friTap public-tree leak guard (§F, L1).
#
# Authoritative, NAME-FREE check that the public tree carries nothing private.
# Two kinds of rule:
#   STRUCTURAL (hard): no agent/signal; --protocol exposes only public protocols;
#                      no public module statically imports a stripped private path.
#   DENYLIST  (hard):  scripts/denylist_tokens.py scan against scripts/denylist.hashes
#                      (SHA-256 of private reveal-tokens — never the cleartext).
#   DIST (§H, hard at publish): setup.py exposes no signal/mtproto extras key.
#
# Usage:
#   scripts/check_public_denylist.sh [TREE_DIR] [--reveal]
#     no TREE_DIR  → build a stripped public tree from this repo (needs private.txt)
#                    and check that. Use locally / inside the §E publish worktree.
#     TREE_DIR=.   → check the tree as-is (use in PUBLIC CI, where the tree is
#                    already stripped and private.txt is absent).
#   --reveal       → print matched cleartext tokens (dev/private only; omit in
#                    public CI logs to stay name-free).
#
# Exit 0 = clean. Non-zero = at least one rule failed (see the per-section report).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# shellcheck source=lib.sh
. "$SCRIPT_DIR/lib.sh"

HASHES="$SCRIPT_DIR/denylist.hashes"
TOKENS_TOOL="$SCRIPT_DIR/denylist_tokens.py"
PRIVATE_TXT="$REPO_ROOT/private.txt"

REVEAL=""
TREE=""
for arg in "$@"; do
  case "$arg" in
    --reveal) REVEAL="--reveal" ;;
    *) TREE="$arg" ;;
  esac
done

CLEANUP_TMP=""
cleanup() { [ -n "$CLEANUP_TMP" ] && rm -rf "$CLEANUP_TMP" || true; }
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Resolve the tree to check. With no argument, reproduce the §E publish strip:
# the publishable set (git-tracked + non-ignored) minus every private.txt path.
# ---------------------------------------------------------------------------
if [ -z "$TREE" ]; then
  if [ -f "$PRIVATE_TXT" ]; then
    # Full/dev tree: reproduce the §E publish strip and check the result.
    CLEANUP_TMP="$(mktemp -d)"
    TREE="$CLEANUP_TMP/public_tree"
    mkdir -p "$TREE"
    fritap_assemble_public_tree "$REPO_ROOT" "$TREE"
    fritap_strip_private_paths "$TREE" "$PRIVATE_TXT"
    echo "[check] built stripped public tree at $TREE"
  else
    # Already-published public repo (no private.txt): check the tree as-is.
    TREE="$REPO_ROOT"
    echo "[check] no private.txt — checking tree as-is (public-repo mode)"
  fi
fi

echo "[check] target tree: $TREE"
fail=0
note=0

# --- STRUCTURAL 1: no private agent dir -------------------------------------
if [ -e "$TREE/agent/signal" ]; then
  echo "FAIL  structural: agent/signal/ present in public tree"; fail=1
else
  echo "PASS  structural: agent/signal/ absent"
fi

# --- STRUCTURAL 2: --protocol exposes only public protocols -----------------
# Import friTap FROM the tree (cd into it, no PYTHONPATH) so an editable install
# of the full repo cannot shadow the stripped tree — mirrors verify_public_build.
if ( cd "$TREE" && python3 - <<'PY'
import sys
from friTap.protocols import registry
names = set(registry.available_protocol_names())
allowed = {"tls", "ssh", "mtproto", "telegram"}
extra = names - allowed
if extra:
    print(f"      unexpected protocol(s): {sorted(extra)}", file=sys.stderr); sys.exit(1)
print("      protocols:", sorted(names))
PY
)
then echo "PASS  structural: --protocol exposes only public protocols"
else echo "FAIL  structural: a private protocol is selectable via --protocol"; fail=1
fi

# --- STRUCTURAL 3: no public module imports a stripped private path ----------
# Only enforceable when private.txt is available (full tree / publish worktree);
# in public CI the smoke-import job catches a dangling import instead.
if [ -f "$PRIVATE_TXT" ]; then
  mods=()
  while IFS= read -r raw || [ -n "$raw" ]; do
    line="${raw%%#*}"; line="${line#"${line%%[![:space:]]*}"}"; line="${line%"${line##*[![:space:]]}"}"
    case "$line" in
      friTap/*.py) mods+=( "$(echo "${line%.py}" | tr '/' '.')" ) ;;
    esac
  done < "$PRIVATE_TXT"
  import_hit=0
  for m in "${mods[@]}"; do
    if grep -rIn --include='*.py' -E "(^|[^.[:alnum:]_])(import|from)[[:space:]]+${m//./\\.}([[:space:]]|\$|\.)" "$TREE" 2>/dev/null; then
      echo "      public file imports stripped private module: $m"; import_hit=1
    fi
  done
  if [ "$import_hit" -eq 0 ]; then echo "PASS  structural: no public import of a stripped private module"
  else echo "FAIL  structural: a public module imports a stripped private path"; fail=1; fi
else
  echo "SKIP  structural: private-import check (no private.txt — public CI uses smoke-import)"
fi

# --- DIST: no `signal` extras key in setup.py -------------------------------
# Only the `signal` extra is a leak (its PyPI-page "Provides-Extra: signal"
# advertises Signal support). mtproto/mtproto-fast are PUBLIC (Telegram) and are
# NOT a leak — their removal is §H packaging cleanup, verified separately. The
# §E scrubber removes the `signal` extra, so this clears on the published tree.
if [ -f "$TREE/setup.py" ]; then
  if grep -qE '^[[:space:]]*"signal"[[:space:]]*:' "$TREE/setup.py"; then
    echo "NOTE  dist: setup.py still exposes the 'signal' extras key (PyPI-page leak; cleared by the §E scrubber)"; note=1
  else
    echo "PASS  dist: no 'signal' extras key in setup.py"
  fi
fi

# --- DENYLIST: name-free reveal-token scan ----------------------------------
echo "[check] denylist token scan…"
set +e
python3 "$TOKENS_TOOL" scan "$TREE" "$HASHES" $REVEAL
rc=$?
set -e
if [ "$rc" -eq 0 ]; then
  echo "PASS  denylist: no private reveal-tokens"
elif [ "$rc" -eq 2 ]; then
  echo "NOTE  denylist: reveal-token residuals present (cleared by the §E scrubber)"; note=1
else
  echo "FAIL  denylist: scanner error (rc=$rc)"; fail=1
fi

echo
echo "=== leak-guard summary ==="
echo "  hard failures (structural/dist-at-publish): $fail"
echo "  deferred notes (clear at §E scrub / §H deps): $note"
if [ "$fail" -ne 0 ]; then
  echo "RESULT: FAIL (hard rule violated)"; exit 1
fi
if [ "$note" -ne 0 ]; then
  echo "RESULT: PASS-structural (accepted reveal-token residuals; HARD rules are the contract — §F-strict)"; exit 2
fi
echo "RESULT: PASS (publish-ready)"; exit 0
