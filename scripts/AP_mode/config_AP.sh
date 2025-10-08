#!/usr/bin/env bash


# ----------- FIRST TIME CONFIG -------------

#1. Is dnsmasq installed?
PKG="dnsmasq"

if ! dpkg -s "$PKG" >/dev/null 2>&1; then
  echo "First time setup: installing $dnsmasq now..."
  sudo apt-get update -y
  sudo apt-get install -y "$PKG"
fi

#2. Is IPv4 forwarding enabled at the kernel level?

CONF="/etc/sysctl.d/99-ipforward.conf"
LINE="net.ipv4.ip_forward=1"

# create conf file if missing or corrupt
if [ ! -f "$CONF" ] || ! grep -qx "$LINE" "$CONF"; then
  echo "First time setup: Ensuring $CONF contains correct setting..."
  sudo rm -f "$CONF"
  echo "$LINE" | sudo tee "$CONF" >/dev/null
  sudo sysctl --system >/dev/null
fi

#3. Is the start_hostapd service installed?
SERVICE="/etc/systemd/system/start_hostapd.service"
SCRIPT="/usr/local/bin/start_hostapd.sh"

if [ ! -f "$SERVICE" ] || [ ! -f "$SCRIPT" ]; then
  echo "First time setup: Installing start_hostapd service and script"
  sudo mkdir -p /usr/local/etc
  sudo cp $SCRIPT_DIR/../helpers/AP/services/start_hostapd.service /etc/systemd/system/
  sudo cp $SCRIPT_DIR/../helpers/AP/services/start_hostapd.sh /usr/local/bin/
  sudo cp $SCRIPT_DIR/../helpers/AP/configs/hostapd.conf /usr/local/etc/hostapd.conf
  sudo chmod +x /usr/local/bin/start_hostapd.sh
  sudo systemctl daemon-reload
fi

#4. Is the static IP service installed?
SERVICE="/etc/systemd/system/static_ip.service"
SCRIPT="/usr/local/bin/assign_wlan1_ip.sh"

if [ ! -f "$SERVICE" ] || [ ! -f "$SCRIPT" ]; then
  echo "First time setup: Installing start_hostapd service and script"
  sudo cp $SCRIPT_DIR/../helpers/AP/services/static_ip.service /etc/systemd/system/
  sudo cp $SCRIPT_DIR/../helpers/AP/services/assign_wlan1_ip.sh /usr/local/bin/
  sudo chmod +x /usr/local/bin/assign_wlan1_ip.sh
  sudo systemctl daemon-reload
fi
