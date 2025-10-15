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

#GATEWAY MODE: NAT FORWARD & dnsmasq
if [[ "$MODE" == "gateway" ]]; then
    #create a flag telling the system gateway mode is on
    echo "gateway=active" > /usr/local/etc/80211s_gateway_status.txt

    #Enable NAT forwarding
    /usr/local/bin/toggle_NAT_80211s.sh --on

    ##Start DHCP server
    cp /usr/local/etc/dnsmasq_DHCP.conf.80211s.disabled /etc/dnsmasq.d/lan-wlan1.conf
    #restart dnsmasq if active, if inactive then start
    enabled="$(systemctl is-enabled dnsmasq)"
    if [[ "$enabled" != "enabled" ]]; then
       systemctl enable --now dnsmasq
    else
       systemctl restart dnsmasq
    fi
    echo "DHCP server enabled"

    #assign static IP and persist
    cp /usr/local/etc/10-wlan1.network.80211s.disabled /etc/systemd/network/10-wlan1.network
    systemctl enable systemd-networkd
    systemctl start systemd-networkd
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

#Additional settings for gateway mode
if [[ "$MODE" == "gateway" ]]; then
  #serve DNS servers over wlan1
  /usr/local/bin/gateway_serve_DNS.sh
fi

#Additional settings for client conf
####Upon failure, these should periodically retry, in case the gateway goes down and comes back up
if [[ "$MODE" == "client" ]]; then
  #get DHCP lease
  dhclient -i wlan1
  #todo: get and apply DNS settings
fi
