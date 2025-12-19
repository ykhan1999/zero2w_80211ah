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

#same command to update config regardless of mode - hotspot ssid/pass won't do anything in gateway mode
${SCRIPT_DIR}/../../../scripts/mesh_80211s/config_mesh.sh --hotspot-ssid "${REG_SSID}" --hotspot-password "${REG_PW}" --halow-ssid "${HALOW_SSID}" --halow-password "${HALOW_PW}"

#now we differentiate
if [ "$MODE" == "gateway" ]; then
  #need to connect to gateway network
  nmcli device wifi connect "${REG_SSID}" password "${REG_PW}" ifname wlan0
  #only one script active at a time
  ${SCRIPT_DIR}/../../../scripts/mesh_80211s/disable_mesh.sh
  ${SCRIPT_DIR}/../../../scripts/mesh_80211s/enable_mesh_gateway.sh
elif [ "$MODE" == "client" ]; then
  ${SCRIPT_DIR}/../../../scripts/mesh_80211s/disable_mesh.sh
  ${SCRIPT_DIR}/../../../scripts/mesh_80211s/enable_mesh_client.sh
else
  exit 1
fi
