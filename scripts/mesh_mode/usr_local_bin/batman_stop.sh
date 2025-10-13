#!/usr/bin/env bash

FILE="/usr/local/etc/batman_gateway_status.txt"

#deactivate gateway if active
if [[ -f "$FILE" ]] && grep -q "gateway=active" "$FILE"; then
    echo "Gateway is active. Turning off NAT forwarding and DHCP server..."
    /usr/local/bin/toggle_NAT_batman.sh --off
    rm -r /usr/local/etc/batman_gateway_status.txt
fi

###for gateway or client

#remove bat0 interface
batctl if del wlan1
batctl meshif bat0 interface destroy

#Stop wpa_supplicant
pkill -f 'wpa_supplicant_s1g'

#flush static IP
ip link set wlan1 down
ip addr flush dev wlan1
ip link set wlan1 up

#unload batman driver
modprobe -r batman-adv
