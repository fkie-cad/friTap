#!/bin/bash
# Scaffold for the outcome cases: copy the audit fixture into the run's empty
# workspace (the friTap MCP server is confined to it via --root).
set -euo pipefail
fixtures="$(cd "$(dirname "$0")/../../fixtures" && pwd)"
cp "$fixtures/audit.tap" "$fixtures/phases.jsonl" .
