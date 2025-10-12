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

#wait before bringing up AP
sleep 1

#bring up AP
hostapd_s1g -t /usr/local/etc/hostapd.conf

#if not running after 10s, try to bring up again
while true; do
  sleep 10
  PID=$(pgrep -x hostapd_s1g)

  if [[ -n "$PID" ]]; then
    echo "hostapd_s1g is running with PID $PID"
    break
  else
    echo "hostapd_s1g not yet running... retrying in 10s"
  fi
done

