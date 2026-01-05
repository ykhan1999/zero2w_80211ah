#!/usr/bin/env bash

#update package cache
sudo apt-get update

#install dependencies for mesh scripts
sudo apt install -y isc-dhcp-client=4.4.3-P1-8

#Enable IPv4 forwarding at kernel level

CONF="/etc/sysctl.d/99-ipforward.conf"
LINE="net.ipv4.ip_forward=1"

if [ ! -f "$CONF" ] || ! grep -qx "$LINE" "$CONF"; then
  echo "First time setup: Enable ipv4 forward at kernel level..."
  sudo rm -f "$CONF"
  echo "$LINE" | sudo tee "$CONF" >/dev/null
  sudo sysctl --system >/dev/null
  echo "ipv4 forwarding capability enabled!"
fi

#copy scripts to system directories
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

sudo cp ${SCRIPT_DIR}/../mesh_80211s/disable_mesh.sh /usr/local/bin/
sudo cp ${SCRIPT_DIR}/../mesh_80211s/enable_mesh_gateway.sh /usr/local/bin/
sudo cp ${SCRIPT_DIR}/../mesh_80211s/enable_mesh_client.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/disable_mesh.sh
sudo chmod +x /usr/local/bin/enable_mesh_gateway.sh
sudo chmod +x /usr/local/bin/enable_mesh_client.sh
