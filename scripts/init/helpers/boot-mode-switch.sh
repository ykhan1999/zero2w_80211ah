#!/usr/bin/env bash
set -euo pipefail

WEB_FRONTEND="webserver-frontend.service"
WEB_BACKEND="webserver-backend.service"
GW="80211s_gateway.service"
CL="80211s_client.service"

log() { echo "[boot-mode-switch] $*"; }

#create lock to stop 80211s_client and 80211s_gateway from starting right away
mkdir -p /run/boot-mode
touch /run/boot-mode/lock

#show setup prompt on screen
/usr/local/bin/disp_setup.sh || true

#start WiFi Setup
nmcli connection add \
  type wifi \
  ifname wlan0 \
  con-name wifi-setup-open \
  ssid "WiFi Setup"

nmcli connection modify wifi-setup-open \
  802-11-wireless.mode ap \
  wifi-sec.key-mgmt none \
  ipv4.method auto \
  ipv6.method disabled

nmcli connection up wifi-setup-open

# Start webserver right away
log "Starting webserver services: $WEB_FRONTEND $WEB_BACKEND"
systemctl enable --now "$WEB_FRONTEND" "$WEB_BACKEND" || true

if [[ $(systemctl is-enabled --quiet "$GW") || $(systemctl is-enabled --quiet "$CL") ]]; then
  i=0
  while true; do
    /usr/local/bin/disp_setup_timer.sh $((60-$i))
    sleep 1
    i=$(($i+1))
        if [ $i -gt 59 ]; then
            break
        fi
  done

  log "Mesh mode enabled (gateway=$gw_enabled client=$cl_enabled). Stopping webserver..."
  systemctl stop "$WEB_FRONTEND" "$WEB_BACKEND" || true
  systemctl disable "$WEB_FRONTEND" "$WEB_BACKEND" || true

  if [[ $(systemctl is-enabled --quiet "$GW") ]]; then
    log "Starting $GW"
    systemctl start "$GW"
    nmcli connection down wifi-setup-open
    nmcli connection delete wifi-setup-open
    rm -f /run/boot-mode/lock
 else
    log "Starting $CL"
    systemctl start "$CL"
    nmcli connection down wifi-setup-open
    nmcli connection delete wifi-setup-open
    rm -f /run/boot-mode/lock
  fi

else
  log "Neither $GW nor $CL is enabled. Keeping webserver running."

fi

log "Done."
