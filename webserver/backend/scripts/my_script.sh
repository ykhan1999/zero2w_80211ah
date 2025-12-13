#!/usr/bin/env bash
set -euo pipefail

# Super tiny demo parser
MODE=""
TARGET=""
VERBOSITY="normal"
DRY_RUN="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --target) TARGET="$2"; shift 2 ;;
    --verbosity) VERBOSITY="$2"; shift 2 ;;
    --dry-run) DRY_RUN="true"; shift 1 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

echo "MODE=$MODE"
echo "TARGET=$TARGET"
echo "VERBOSITY=$VERBOSITY"
echo "DRY_RUN=$DRY_RUN"

# do real work here...
