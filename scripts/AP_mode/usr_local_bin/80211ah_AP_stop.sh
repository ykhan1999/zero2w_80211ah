#!/usr/bin/env bash

#Stop hostapd, try gracefully
PID=$(pgrep -x hostapd_s1g)
sudo kill -TERM "$PID"

for i in {1..10}; do
  if ! ps -p "$PID" > /dev/null; then
    echo "hostapd_s1g terminated gracefully."
    exit 0
  fi
  sleep 1
done

if ps -p "$PID" > /dev/null; then
  echo "Graceful shutdown timed out. Forcing termination..."
  sudo kill -KILL "$PID"
  sleep 1
fi

#Disable NAT forwarding and DHCP server
/usr/local/bin/toggle_NAT.sh --off

#remove static ip
sudo ip link set wlan1 down
sudo ip addr flush dev wlan1
sudo ip link set wlan1 up
