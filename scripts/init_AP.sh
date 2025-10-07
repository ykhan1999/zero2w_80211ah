#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

#service start hostapd
sudo cp $SCRIPT_DIR/AP_helpers/start_hostapd.service /etc/systemd/system/
sudo cp $SCRIPT_DIR/AP_helpers/start_hostapd.sh /usr/local/bin/
sudo cp $SCRIPT_DIR/../sample_configs/hostapd.conf /usr/local/etc/hostapd.conf
sudo chmod +x /usr/local/bin/start_hostapd.sh
sudo systemctl daemon-reload

#service to assign static IP
sudo cp $SCRIPT_DIR/AP_helpers/static_ip.service /etc/systemd/system/
sudo cp $SCRIPT_DIR/AP_helpers/assign_wlan1_ip.sh /usr/local/bin
sudo chmod +x /usr/local/bin/assign_wlan1_ip.sh
sudo systemctl daemon-reload

#Install dnsmasq for NAT forwarding
apt-get update -y >/dev/null && apt-get install -y dnsmasq >/dev/null

#Enable IPv4 forwarding at the level of the kernel
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-ipforward.conf
sudo sysctl --system

