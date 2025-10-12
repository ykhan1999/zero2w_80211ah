#!/usr/bin/env bash

#Stop hostapd, try gracefully
PID=$(pgrep -x hostapd_s1g)
kill -TERM "$PID"

for i in {1..10}; do
  if ! ps -p "$PID" > /dev/null; then
    echo "hostapd_s1g terminated gracefully."
    exit 0
  fi
  sleep 1
done

if ps -p "$PID" > /dev/null; then
  echo "Graceful shutdown timed out. Forcing termination..."
  kill -KILL "$PID"
  sleep 1
fi

#Disable NAT forwarding and DHCP server
/usr/local/bin/toggle_NAT.sh --off

#remove static ip
ip link set wlan1 down
ip addr flush dev wlan1
ip link set wlan1 up
