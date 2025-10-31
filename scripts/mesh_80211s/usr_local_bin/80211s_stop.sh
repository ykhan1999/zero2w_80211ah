#!/usr/bin/env bash

###for gateway or client
#Stop wpa_supplicant
pkill -f 'wpa_supplicant_s1g'

###for gateway
#deactivate NAT forwarding
FILE="/usr/local/etc/80211s_gateway_status.txt"
if [[ -f "$FILE" ]] && grep -q "gateway=active" "$FILE"; then
    #stop serving DNS names
    pkill -f "python3 -m http.server $PORT" 2>/dev/null
    systemctl stop 80211s_serve_dns
    systemctl disable 80211s_serve_dns

    #disable NAT forwarding
    echo "Gateway is active. Turning off NAT forwarding and DHCP server..."
    /usr/local/bin/toggle_NAT_80211s.sh --off

    #remove static IP daemon and DHCP server
    rm -r /etc/systemd/network/10-wlan1.network
    systemctl stop systemd-networkd
    systemctl disable systemd-networkd

    #disable gateway flag
    rm -r /usr/local/etc/80211s_gateway_status.txt
else
###for client mode
    #disable NAT forwarding
    /usr/local/bin/toggle_NAT_80211ac.sh --off

    #remove static IP and DHCP
    rm -r /etc/systemd/network/10-wlan0.network
    systemctl stop systemd-networkd
    systemctl disable systemd-networkd

    #give networkmanager control again of wlan0
    cp /usr/local/etc/netman_unmanaged.conf.80211s.disabled /etc/NetworkManager/conf.d/unmanaged.conf
    systemctl restart NetworkManager
fi

#flush current IP
ip link set wlan1 down
ip addr flush dev wlan1
ip link set wlan1 up

ip link set wlan0 down
ip addr flush dev wlan0
ip link set wlan0 up
