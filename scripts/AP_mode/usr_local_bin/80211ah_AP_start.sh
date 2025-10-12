#!/usr/bin/env bash

#restart driver module for fresh bringup
systemctl stop start_morse
modprobe -r morse
systemctl restart start_morse
echo "Driver module restarted"

#set static IP for wlan1
ip addr flush dev wlan1
ip addr add 192.168.50.1/24 dev wlan1
ip link set wlan1 up

#enable NAT forward and DHCP server for wlan1
/usr/local/bin/toggle_NAT.sh --on

#bring up AP
hostapd_s1g -t /usr/local/etc/hostapd.conf
