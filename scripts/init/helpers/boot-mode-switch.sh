#!/usr/bin/env bash

#set env variables
WEB_FRONTEND="webserver-frontend.service"
WEB_BACKEND="webserver-backend.service"
GW="80211s_gateway.service"
CL="80211s_client.service"

log() { echo "[boot-mode-switch] $*"; }

#create lock to stop 80211s_client and 80211s_gateway from starting right away
mkdir -p /run/boot-mode
touch /run/boot-mode/lock

#start WiFi Setup
nmcli connection down wifi-setup-open || true
nmcli connection delete wifi-setup-open || true

#random pw
psk=$(cat /dev/urandom | tr -dc a-z0-9 | head -c 8)

nmcli connection add \
  type wifi \
  ifname wlan0 \
  con-name wifi-setup-open \
  ssid "ExtendFi"

nmcli connection modify wifi-setup-open \
  802-11-wireless.mode ap \
  wifi-sec.key-mgmt wpa-psk \
  wifi-sec.psk "$psk" \
  ipv4.method auto \
  ipv6.method disabled

nmcli connection up wifi-setup-open
/usr/local/bin/disp_setup.sh || true
/usr/local/bin/disp_custom_msg.sh --line3 "PW: ${psk}" || true

# Start webserver right away if not already started
log "Starting webserver services: $WEB_FRONTEND $WEB_BACKEND"
systemctl enable --now "$WEB_FRONTEND" "$WEB_BACKEND" || true

#if gateway or client already enabled, give the user some time to reconfigure if desired, otherwise continue with previous settings
if [[ $(systemctl is-enabled "$GW") == "enabled" || $(systemctl is-enabled "$CL") == "enabled" ]]; then
  #show reconfigure prompt on screen
  /usr/local/bin/disp_custom_msg.sh --line1 "To reconfigure:" || true
  i=0
  #wait 100 seconds
  while true; do
    /usr/local/bin/disp_setup_timer.sh $((100-$i)) || true
    sleep 1
    i=$(($i+1))
        if [ $i -gt 99 ]; then
          if [[ $(systemctl is-enabled "$GW") == "enabled" ]]; then
            /usr/local/bin/disp_custom_msg.sh --line4 "Starting gateway..." || true
          fi
          if [[ $(systemctl is-enabled "$CL") == "enabled" ]]; then
            /usr/local/bin/disp_custom_msg.sh --line4 "Starting client..." || true
          fi
        break
        fi
  done

  #enable gateway or client depending on what was configured, reboot if both are configured
  if [[ $(systemctl is-enabled "$GW") == "enabled" ]]; then
    log "Starting $GW"
    /usr/local/bin/disp_mode_gw.sh || true
    /usr/local/bin/disp_connecting.sh || true
    nmcli connection down wifi-setup-open
    nmcli connection delete wifi-setup-open
    log "stopped hotspot"
    /usr/local/bin/enable_mesh_gateway.sh &
    log "launched gateway service"
  elif [[ $(systemctl is-enabled "$CL") == "enabled" ]]; then
    log "Starting $CL"
    /usr/local/bin/disp_mode_client.sh || true
    /usr/local/bin/disp_connecting.sh || true
    nmcli connection down wifi-setup-open
    nmcli connection delete wifi-setup-open
    log "stopped hotspot"
    /usr/local/bin/enable_mesh_client.sh &
    log "launched client service"
  else
    reboot
  fi

#logic for first time setup
else
  #show setup prompt on screen
  log "Neither $GW nor $CL is enabled. Keeping webserver running."
fi

log "Done."
