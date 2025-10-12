#!/usr/bin/env bash

#helper to get current dir

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# ----------- FIRST TIME CONFIG -------------

#1. Is dnsmasq installed?
PKG="dnsmasq"

if ! dpkg -s "$PKG" >/dev/null 2>&1; then
  echo "First time setup: installing $PKG now..."
  sudo apt-get update -y
  sudo apt-get install -y "$PKG"
  echo "$PKG installed!"
fi

#2. Is IPv4 forwarding enabled at the kernel level?

CONF="/etc/sysctl.d/99-ipforward.conf"
LINE="net.ipv4.ip_forward=1"

# create conf file if missing or corrupt
if [ ! -f "$CONF" ] || ! grep -qx "$LINE" "$CONF"; then
  echo "First time setup: Enable ipv4 forward at kernel level..."
  sudo rm -f "$CONF"
  echo "$LINE" | sudo tee "$CONF" >/dev/null
  sudo sysctl --system >/dev/null
  echo "ipv4 forwarding capability enabled!"
fi

#3. Is the 80211ah_AP service installed?
SERVICE="/etc/systemd/system/80211ah_AP.service"

if [ ! -f "$SERVICE" ]; then
  echo "First time setup: Installing 80211ah_AP service and script"
  sudo mkdir -p /usr/local/etc
  sudo cp $SCRIPT_DIR/services/80211ah_AP.service /etc/systemd/system/
  sudo cp $SCRIPT_DIR/usr_local_bin/80211ah_AP_start.sh /usr/local/bin/
  sudo cp $SCRIPT_DIR/usr_local_bin/80211ah_AP_stop.sh /usr/local/bin/
  sudo cp $SCRIPT_DIR/usr_local_bin/toggle_NAT.sh /usr/local/bin/
  sudo cp $SCRIPT_DIR/config/hostapd.conf /usr/local/etc/hostapd.conf
  sudo chmod +x /usr/local/bin/80211ah_AP_start.sh
  sudo chmod +x /usr/local/bin/80211ah_AP_stop.sh
  sudo chmod +x /usr/local/bin/toggle_NAT.sh.sh
  sudo systemctl daemon-reload
  echo "done installing 80211ah_AP service!"
fi

#TBD - parse flags for config
