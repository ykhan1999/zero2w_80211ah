#!/usr/bin/env bash
set -euo pipefail

# Super tiny demo parser
MODE=""
REG_SSID=""
REG_PW=""
HALOW_SSID=""
HALOW_PW=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --ssid) REG_SSID="$2"; shift 2 ;;
    --pw) REG_PW="$2"; shift 2 ;;
    --halow-ssid) HALOW_SSID="$2"; shift 2 ;;
    --halow-pw) HALOW_PW="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

echo "$MODE"
echo "$REG_SSID"
echo "$REG_PW"
echo "$HALOW_SSID"
echo "$HALOW_PW"
