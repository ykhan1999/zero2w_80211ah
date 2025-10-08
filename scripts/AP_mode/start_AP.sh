#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

#restart driver module for fresh bringup
sudo systemctl stop start_morse
sudo modprobe -r morse
sudo systemctl restart start_morse
echo "Driver module restarted"

#set static IP for wlan1
sudo systemctl enable static_ip.service
sudo systemctl restart static_ip.service

#enable NAT forward and DHCP server for wlan1
sudo $SCRIPT_DIR/../helpers/AP/toggle_NAT.sh --on

#bring up AP
sudo systemctl enable --now start_hostapd.service
