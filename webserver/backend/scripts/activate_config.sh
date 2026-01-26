#!/usr/bin/env bash

#parser
MODE=""
REG_SSID=""
REG_PW=""
HALOW_SSID=""
HALOW_PW=""
OPTIM=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --ssid) REG_SSID="$2"; shift 2 ;;
    --pw) REG_PW="$2"; shift 2 ;;
    --halow-ssid) HALOW_SSID="$2"; shift 2 ;;
    --halow-pw) HALOW_PW="$2"; shift 2 ;;
    --optim) OPTIM="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

#kill boot mode switch script
pkill -f "boot-mode-switch.sh" || true
pkill -f "disp_setup_timer.sh" || true

#now we differentiate
if [ "$MODE" == "gateway" ]; then
  /usr/local/bin/disp_mode_gw.sh || true
  /usr/local/bin/disp_custom_msg.sh --line2 "Applying settings..." || true
  /usr/local/bin/disp_loading_bar.sh 3 > /dev/null 2>&1 &
  /usr/local/etc/zero2w_80211ah/scripts/mesh_80211s/config_mesh.sh --wifi-ssid "${REG_SSID}" --wifi-password "${REG_PW}" --halow-ssid "${HALOW_SSID}" --halow-password "${HALOW_PW}" --optim "${OPTIM}"
  /usr/local/bin/disp_connecting.sh || true
  nmcli connection down wifi-setup-open || true
  nmcli connection delete wifi-setup-open || true
  /usr/local/bin/disable_mesh.sh
  /usr/local/bin/enable_mesh_gateway.sh
elif [ "$MODE" == "client" ]; then
  /usr/local/bin/disp_mode_client.sh || true
  /usr/local/bin/disp_custom_msg.sh --line2 "Applying settings..." || true
  /usr/local/bin/disp_loading_bar.sh 3 > /dev/null 2>&1 &
  /usr/local/etc/zero2w_80211ah/scripts/mesh_80211s/config_mesh.sh --wifi-ssid "${REG_SSID}" --wifi-password "${REG_PW}" --halow-ssid "${HALOW_SSID}" --halow-password "${HALOW_PW}" --optim "${OPTIM}"
  /usr/local/bin/disp_connecting.sh || true
  nmcli connection down wifi-setup-open || true
  nmcli connection delete wifi-setup-open || true
  /usr/local/bin/disable_mesh.sh
  /usr/local/bin/enable_mesh_client.sh
else
  exit 1
fi
