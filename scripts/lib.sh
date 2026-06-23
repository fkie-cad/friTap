#!/usr/bin/env bash
# scripts/lib.sh — shared helpers for the public-tree publish/verify/guard scripts.
#
# Sourced by publish_public.sh, verify_public_build.sh and check_public_denylist.sh
# to remove the triple-duplicated "assemble publishable set + strip private.txt
# paths" logic. Generic and name-free: this file is tracked and not listed in
# private.txt, so it ships to the public mirror and MUST stay scrub-safe (no
# private terms). Callers run under `set -euo pipefail`; these helpers are safe
# under it.

# Assemble the publishable set into the tree dir ($2) from repo root ($1):
# tracked files PLUS new files that aren't gitignored (honoring .gitignore's
# public-mirror allowlist), which auto-excludes every gitignored runtime
# artifact without enumerating them.
fritap_assemble_public_tree() {
  local repo_root="$1" tree="$2"
  ( cd "$repo_root" && git ls-files --cached --others --exclude-standard -z ) \
    | rsync -a --files-from=- --from0 "$repo_root/" "$tree/"
}

# Strip every glob listed in private.txt ($2) from the public tree ($1).
#   - Skip blank lines and comment lines; strip inline trailing '# ...' comments
#     and surrounding whitespace.
#   - Patterns may contain '*' globs; matching nothing is NOT an error
#     (forward-looking entries may be absent).
# Pass "verbose" as $3 to report "(no match)" / "removed <relpath>" per entry.
fritap_strip_private_paths() {
  local tree="$1" private_txt="$2" verbose="${3:-}"
  local raw line matches match
  # nullglob: non-matching globs expand to nothing instead of literal text.
  shopt -s nullglob
  while IFS= read -r raw || [ -n "$raw" ]; do
    line="${raw%%#*}"; line="${line#"${line%%[![:space:]]*}"}"; line="${line%"${line##*[![:space:]]}"}"
    [ -z "$line" ] && continue
    matches=( "$tree"/$line )
    if [ "${#matches[@]}" -eq 0 ]; then
      [ "$verbose" = verbose ] && echo "  (no match)   $line"
      continue
    fi
    for match in "${matches[@]}"; do
      rm -rf "$match"
      [ "$verbose" = verbose ] && echo "  removed      ${match#"$tree/"}"
    done
  done < "$private_txt"
  shopt -u nullglob
}
