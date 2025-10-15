#!/usr/bin/env bash

#Parse argument for gateway vs client
# Default values
MODE=""

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --gateway)
      MODE="gateway"
      shift
      ;;
    --client)
      MODE="client"
      shift
      ;;
    *)
      echo "Unknown argument: $1"
      exit 1
      ;;
  esac
done

# Check required args
if [[ -z "$MODE" ]]; then
  echo "Usage: $0 --gateway|--client"
  exit 1
fi

#restart driver module for fresh bringup
systemctl stop start_morse
modprobe -r morse
systemctl restart start_morse
echo "Driver module restarted"

#flush static IP if present and set MTU to 1500
ip link set wlan1 down
ip addr flush dev wlan1
ip link set mtu 1500 dev wlan1
ip link set wlan1 up

#cleanup old instance of wpa_supplicant if present
rm -r /var/run/wpa_supplicant_s1g/wlan1 || true

#GATEWAY MODE: NAT FORWARD
if [[ "$MODE" == "gateway" ]]; then
    #Gateway mode: Enable NAT forwarding
    /usr/local/bin/toggle_NAT_80211s.sh --on
fi

#start wpa_supplicant
wpa_supplicant_s1g -D nl80211 -i wlan1 -c /usr/local/etc/halow_80211s.conf -B

#wait for bringup
while true; do
    STATUS=$(wpa_cli_s1g -i wlan1 status 2>/dev/null | grep "wpa_state=COMPLETED")
    if [[ -n "$STATUS" ]]; then
        echo "80211s brought up on wlan1"
        break
    fi
    sleep 1
done

#Additional settings for gateway conf
if [[ "$MODE" == "gateway" ]]; then
    #Start DHCP server
    cp /usr/local/etc/dnsmasq_DHCP.conf.80211s.disabled /etc/dnsmasq.d/lan-wlan1.conf

    #restart dnsmasq if active, if inactive then start
    enabled="$(systemctl is-enabled dnsmasq)"
    if [[ "$enabled" != "enabled" ]]; then
       systemctl enable --now dnsmasq
    else
       systemctl restart dnsmasq
    fi
    echo "DHCP server enabled"

    #add static IP
    ip link set wlan1 down
    ip addr flush dev wlan1
    ip addr add 192.168.50.1/24 dev wlan1
    ip link set wlan1 up

    #create a flag so that the system knows gateway mode is on
    echo "gateway=active" > /usr/local/etc/80211s_gateway_status.txt
fi

#Additional settings for client conf
#if [[ "$MODE" == "client" ]]; then
#    #todo: wait for connection 192.168.10.1 before trying for DHCP lease
#    #Get DHCP lease
#    ip addr flush dev bat0
#    dhclient -v bat0
#    #ip routing test
#    ip route add default via 192.168.10.1 dev bat0 table 10
#fi
