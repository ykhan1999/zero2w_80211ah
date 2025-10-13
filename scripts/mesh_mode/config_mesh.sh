#!/usr/bin/env bash

#helper to get current dir

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# ----------- FIRST TIME CONFIG -------------

#1. Is batctl installed?
PKG="batctl"

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

#3. Is the 80211ah_mesh service installed?
SERVICE1="/etc/systemd/system/batman_mesh_gateway.service"
SERVICE2="/etc/systemd/system/batman_mesh_client.service"

if [ ! -f "$SERVICE1" ] || [ ! -f "$SERVICE2" ] ; then
  echo "First time setup: Installing batman_mesh service and script"
  sudo mkdir -p /usr/local/etc
  sudo cp $SCRIPT_DIR/services/batman_mesh_gateway.service /etc/systemd/system/
  sudo cp $SCRIPT_DIR/services/batman_mesh_client.service /etc/systemd/system/
  sudo cp $SCRIPT_DIR/usr_local_bin/batman_start.sh /usr/local/bin/
  sudo cp $SCRIPT_DIR/usr_local_bin/batman_stop.sh /usr/local/bin/
  sudo cp $SCRIPT_DIR/usr_local_bin/toggle_NAT_batman.sh /usr/local/bin/
  sudo cp $SCRIPT_DIR/config/halow_ibss.conf /usr/local/etc/
  sudo cp $SCRIPT_DIR/config/dnsmasq_DHCP.conf.batman.disabled /usr/local/etc/
  sudo cp $SCRIPT_DIR/config/netman_unmanaged.conf.batman.disabled /usr/local/etc/
  sudo cp $SCRIPT_DIR/config/nftables_forward.conf.batman.disabled /usr/local/etc/
  sudo cp $SCRIPT_DIR/config/nftables_noforward.conf.batman.disabled /usr/local/etc/
  sudo chmod +x /usr/local/bin/batman_start.sh
  sudo chmod +x /usr/local/bin/batman_stop.sh
  sudo chmod +x /usr/local/bin/toggle_NAT_batman.sh
  sudo systemctl daemon-reload
  echo "done installing batman_mesh service!"
fi

