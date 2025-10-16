#!/usr/bin/env bash

#helper to get current dir

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# ----------- FIRST TIME CONFIG -------------

#1. Is python3 installed?
PKG="python3"

if ! dpkg -s "$PKG" >/dev/null 2>&1; then
  echo "First time setup: installing $PKG now..."
  sudo apt-get update -y
  sudo apt-get install -y "$PKG"
  echo "$PKG installed!"
fi

#2. Is dhclient installed?
PKG="isc-dhcp-client"

if ! dpkg -s "$PKG" >/dev/null 2>&1; then
  echo "First time setup: installing $PKG now..."
  sudo apt-get update -y
  sudo apt-get install -y "$PKG"
  echo "$PKG installed!"
fi

#3. Is IPv4 forwarding enabled at the kernel level?

CONF="/etc/sysctl.d/99-ipforward.conf"
LINE="net.ipv4.ip_forward=1"

if [ ! -f "$CONF" ] || ! grep -qx "$LINE" "$CONF"; then
  echo "First time setup: Enable ipv4 forward at kernel level..."
  sudo rm -f "$CONF"
  echo "$LINE" | sudo tee "$CONF" >/dev/null
  sudo sysctl --system >/dev/null
  echo "ipv4 forwarding capability enabled!"
fi

#4. Is the 80211ah_mesh service installed?
SERVICE1="/etc/systemd/system/80211s_mesh_gateway.service"
SERVICE2="/etc/systemd/system/80211s_mesh_client.service"

if [ ! -f "$SERVICE1" ] || [ ! -f "$SERVICE2" ] ; then
  echo "First time setup: Installing 80211s_mesh service and script"
  sudo mkdir -p /usr/local/etc
  sudo cp $SCRIPT_DIR/services/80211s_gateway.service /etc/systemd/system/
  sudo cp $SCRIPT_DIR/services/80211s_client.service /etc/systemd/system/
  sudo cp $SCRIPT_DIR/usr_local_bin/80211s_start.sh /usr/local/bin/
  sudo cp $SCRIPT_DIR/usr_local_bin/80211s_stop.sh /usr/local/bin/
  sudo cp $SCRIPT_DIR/usr_local_bin/toggle_NAT_80211s.sh /usr/local/bin/
  sudo cp $SCRIPT_DIR/usr_local_bin/gateway_serve_DNS.sh /usr/local/bin/
  sudo cp $SCRIPT_DIR/config/halow_80211s.conf /usr/local/etc/
  sudo cp $SCRIPT_DIR/config/netman_unmanaged.conf.80211s.disabled /usr/local/etc/
  sudo cp $SCRIPT_DIR/config/nftables_forward.conf.80211s.disabled /usr/local/etc/
  sudo cp $SCRIPT_DIR/config/nftables_noforward.conf.80211s.disabled /usr/local/etc/
  sudo cp $SCRIPT_DIR/config/10-wlan1.network.80211s.disabled /usr/local/etc/
  sudo chmod +x /usr/local/bin/80211s_start.sh
  sudo chmod +x /usr/local/bin/80211s_stop.sh
  sudo chmod +x /usr/local/bin/toggle_NAT_80211s.sh
  sudo chmod +x /usr/local/bin/gateway_serve_DNS.sh
  sudo rm -r /etc/systemd/network/99-default.link
  sudo systemctl daemon-reload
  echo "done installing 80211s_mesh service!"
fi

#5. Are we keeping NetworkManager from touching the interface?

CONF="/etc/NetworkManager/conf.d/unmanaged.conf"
LINE="unmanaged-devices=interface-name:wlan1"

# create conf file if missing or corrupt
if [ ! -f "$CONF" ] || ! grep -qx "$LINE" "$CONF"; then
  echo "Keeping NetworkManager away from wlan1"
  sudo cp /usr/local/etc/netman_unmanaged.conf.80211s.disabled $CONF
  sudo systemctl restart NetworkManager
fi
