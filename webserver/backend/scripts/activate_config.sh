#!/usr/bin/env bash
set -euo pipefail

#parser
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

#enable config
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

${SCRIPT_DIR}/../../../scripts/mesh_80211s/config_mesh.sh --halow-ssid "${REG_SSID}" --halow-password "${REG_PW}"

echo "$MODE"
echo "$REG_SSID"
echo "$REG_PW"
echo "$HALOW_SSID"
echo "$HALOW_PW"
