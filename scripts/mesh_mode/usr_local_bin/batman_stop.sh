#!/usr/bin/env bash

FILE="/usr/local/etc/batman_gateway_status.txt"

#deactivate gateway if active
if [[ -f "$FILE" ]] && grep -q "gateway=active" "$FILE"; then
    echo "Gateway is active. Turning off NAT forwarding and DHCP server..."
    /usr/local/bin/toggle_NAT_batman.sh --off
    rm -r /usr/local/etc/batman_gateway_status.txt
fi

#for gateway or client

#remove bat0 interface
batctl if del wlan1
batctl meshif bat0 interface destroy

#flush static IP
ip link set wlan1 down
ip addr flush dev wlan1
ip link set wlan1 up

#Stop wpa_supplicant (try gracefully first)
PID=$(pgrep -x wpa_supplicant_s1g)
kill -TERM "$PID"

for i in {1..10}; do
  if ! ps -p "$PID" > /dev/null; then
    echo "wpa_supplicant_s1g terminated gracefully."
    exit 0
  fi
  sleep 1
done

if ps -p "$PID" > /dev/null; then
  echo "Graceful shutdown timed out. Forcing termination..."
  kill -KILL "$PID"
  sleep 1
fi

#unload batman driver
modprobe -r batman-adv
