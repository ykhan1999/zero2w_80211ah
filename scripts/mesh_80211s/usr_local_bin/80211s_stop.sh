#!/usr/bin/env bash

#get 2.4Ghz variables
ssid=""
psk=""

###for gateway or client
#Stop wpa_supplicant
pkill -f 'wpa_supplicant_s1g' || true

###for gateway
#stop serving DNS names
pkill -f "python3 -m http.server" || true
systemctl stop 80211s_serve_dns || true
systemctl disable 80211s_serve_dns || true

#disable NAT forwarding
/usr/local/bin/toggle_NAT_80211s.sh --off --gateway || true

#remove static IP daemon and DHCP server
rm -r /etc/systemd/network/10-wlan1.network || true
systemctl restart systemd-networkd || true

#remove netman connection
nmcli connection down wifi-client-${ssid} || true
nmcli connection delete wifi-client-${ssid} || true

pkill -f "/usr/local/bin/disp_gateway_active.sh" || true

###for client mode
#turn off NAT forwarding
/usr/local/bin/toggle_NAT_80211s.sh --off --client || true

#remove netman connection
nmcli connection down wifi-ap-${ssid} || true
nmcli connection delete wifi-ap-${ssid} || true

pkill -f "/usr/local/bin/disp_client_active.sh" || true

#flush current IP
ip link set wlan1 down
ip addr flush dev wlan1
ip link set wlan1 up


