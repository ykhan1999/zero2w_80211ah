#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

#Stop hostapd gracefully
sudo systemctl stop start_hostapd.service
#Disable system services
sudo systemctl disable start_hostapd.service

#Disable NAT forwarding and DHCP server
sudo $SCRIPT_DIR/../helpers/AP/toggle_NAT.sh --off

#disable static ip assignment
sudo systemctl disable static_ip.service

#remove static ip
sudo ip link set wlan1 down
sudo ip addr flush dev wlan1
sudo ip link set wlan1 up
