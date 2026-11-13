#!/usr/bin/env bash
# Run the friTap plugin eval suite (see evals/README.md).
#
# `claude plugin eval` refuses plugin roots with > 20000 entries, and a dev
# checkout (env/, node_modules/) is far larger. So this stages a slim plugin
# root -- the manifest, the skills and this eval suite -- in a temp dir, runs
# the eval there and writes the results back to evals/results/<timestamp>/.
#
# Usage: evals/run.sh [claude plugin eval options...]
#   evals/run.sh --tag trigger --runs 3 --threshold 0.8 --max-cost-usd 5
#   evals/run.sh --tag outcome --runs 3 --max-cost-usd 5
# Outcome cases start the real `fritap mcp` server; the needed grants
# (--scaffold --mocks off --allow-tools mcp__plugin_fritap_fritap__*) are added
# automatically when --tag outcome or --case outcome-* is given.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
stage="$(mktemp -d "${TMPDIR:-/tmp}/fritap-eval.XXXXXX")"
trap 'rm -rf "$stage"' EXIT

mkdir -p "$stage/friTap"
cp -R "$repo/.claude-plugin" "$stage/"
cp -R "$repo/friTap/skills" "$stage/friTap/"
rsync -a --exclude results "$repo/evals/" "$stage/evals/"

# The plugin's MCP server is the `fritap` command: prefer the dev virtualenv.
[[ -x "$repo/env/bin/fritap" ]] && export PATH="$repo/env/bin:$PATH"

extra=()
if [[ " $* " == *" outcome"* || " $* " == *"outcome-"* ]]; then
  extra=(--scaffold --mocks off --allow-tools 'mcp__plugin_fritap_fritap__*')
fi

out="$repo/evals/results/$(date -u +%Y-%m-%dT%H-%M-%SZ)"
mkdir -p "$out"
cd "$stage"
claude plugin eval . --trust-plugin --output-dir "$out" --report "$out/report.html" \
  ${extra[@]+"${extra[@]}"} "$@"
