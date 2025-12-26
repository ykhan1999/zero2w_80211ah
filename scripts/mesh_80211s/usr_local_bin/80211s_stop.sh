#!/usr/bin/env bash

#get 2.4Ghz variables
ssid=""
psk=""

###for gateway or client
#Stop wpa_supplicant
pkill -f 'wpa_supplicant_s1g'

###for gateway
#deactivate NAT forwarding
FILE="/usr/local/etc/80211s_gateway_status.txt"
if [[ -f "$FILE" ]] && grep -q "gateway=active" "$FILE"; then
    #stop serving DNS names
    pkill -f "python3 -m http.server" 2>/dev/null
    systemctl stop 80211s_serve_dns
    systemctl disable 80211s_serve_dns

    #disable NAT forwarding
    echo "Gateway is active. Turning off NAT forwarding and DHCP server..."
    /usr/local/bin/toggle_NAT_80211s.sh --off --gateway

    #remove static IP daemon and DHCP server
    rm -r /etc/systemd/network/10-wlan1.network
    systemctl restart systemd-networkd

    #disable gateway flag
    rm -r /usr/local/etc/80211s_gateway_status.txt

    #remove netman connection
    nmcli connection down wifi-client-${ssid}
    nmcli connection delete wifi-client-${ssid}

    pkill -f "/usr/local/bin/disp_gateway_active.sh"
else
###for client mode
    #turn off NAT forwarding
    /usr/local/bin/toggle_NAT_80211s.sh --off --client

    #remove netman connection
    nmcli connection down wifi-ap-${ssid}
    nmcli connection delete wifi-ap-${ssid}

    pkill -f "/usr/local/bin/disp_client_active.sh"
fi

#flush current IP
ip link set wlan1 down
ip addr flush dev wlan1
ip link set wlan1 up


