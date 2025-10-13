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

#flush static IP if present
ip link set wlan1 down
ip addr flush dev wlan1
ip link set wlan1 up

#load BATMAN driver
modprobe batman-adv

#start wpa_supplicant
wpa_supplicant_s1g -i wlan1 -c /usr/local/etc/halow_ibss.conf -B

#wait for IBSS bringup
while true; do
    STATUS=$(wpa_cli_s1g -i wlan1 status 2>/dev/null | grep "wpa_state=COMPLETED")
    if [[ -n "$STATUS" ]]; then
        echo "IBSS brought up on wlan1"
        break
    fi
    sleep 1
done

#associate batman on wlan1
batctl if add wlan1

#set up bat0 interface
ip link set up dev wlan1
ip link set up dev bat0

#Additional settings for gateway conf
if [[ "$MODE" == "gateway" ]]; then
    #Gateway mode: assign static IP
    ip addr flush dev bat0
    ip addr add 192.168.10.1/24 dev bat0

    #Gateway mode: IP forwarding and DHCP server
    /usr/local/bin/toggle_NAT_batman.sh --on

    #Gateway mode: advertise as a server
    batctl gw server

    #create a flag so that the system knows gateway mode is on
    echo "gateway=active" > /usr/local/etc/batman_gateway_status.txt
fi

