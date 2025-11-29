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

#GATEWAY MODE: NAT FORWARD, DHCP, and static IP
if [[ "$MODE" == "gateway" ]]; then
    #create a flag telling the system gateway mode is on
    echo "gateway=active" > /usr/local/etc/80211s_gateway_status.txt

    #Enable NAT forwarding
    /usr/local/bin/toggle_NAT_80211s.sh --on --gateway

    #assign persistent DHCP server and static IP
    cp /usr/local/etc/10-wlan1.network.80211s.disabled /etc/systemd/network/10-wlan1.network
    #restart or start systemd-networkd
    enabled="$(systemctl is-enabled systemd-networkd)"
    if [[ "$enabled" != "enabled" ]]; then
       systemctl enable --now systemd-networkd
    else
       systemctl restart systemd-networkd
    fi
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
  #begin serving DNS
  enabled="$(systemctl is-enabled 80211s_serve_dns)"
  if [[ "$enabled" != "enabled" ]]; then
     systemctl enable --now 80211s_serve_dns
  else
     systemctl restart 80211s_serve_dns
  fi
  #make sure we have an IP
  while true; do
      if ! ip addr show wlan1 | grep -q "inet "; then
        systemctl restart systemd-networkd
      fi
      sleep 1
  done
fi

#Additional settings for client conf
if [[ "$MODE" == "client" ]]; then
  #####start AP for wlan0
  #keep netman out of the way
  systemctl stop NetworkManager.service
  systemctl disable NetworkManager.service
  #Start AP on wlan0
  rm -r /var/run/wpa_supplicant/wlan0 || true
  wpa_supplicant -D nl80211 -i wlan0 -c /usr/local/etc/2.4_80211.conf -B
  #enable DHCP server on wlan0
  cp /usr/local/etc/10-wlan0.network.80211s.disabled /etc/systemd/network/10-wlan0.network
  #restart or start systemd-networkd
  enabled="$(systemctl is-enabled systemd-networkd)"
  if [[ "$enabled" != "enabled" ]]; then
      systemctl enable --now systemd-networkd
  else
      systemctl restart systemd-networkd
  fi
  #enable NAT forwarding
  /usr/local/bin/toggle_NAT_80211s.sh --on --client

  #####DHCP settings for wlan0
  #counter var for use later
  counter=59
  while true; do
    #get DHCP lease if it exists
    if ! ip addr show wlan1 | grep -q "inet "; then
        dhclient -i wlan1 || true
    fi
    #make sure we have an IP for wlan0
    if ! ip addr show wlan0 | grep -q "inet "; then
    systemctl restart systemd-networkd
    fi
    #at start and every minute, check that our dns servers are correct, and update if not
    counter=$(($counter + 1))
    if [[ $counter -ge 60 ]]; then
      #reset counter
      counter=0
      #init variables to connect to host
      HOST="192.168.50.1"
      PORT=8080
      REMOTE_FILE="nameservers.conf"
      URL="http://${HOST}:${PORT}/${REMOTE_FILE}"
      #get host DNS server file if it exists and we have an IP
      if ip addr show wlan1 | grep -q "inet "; then
      wget $URL --output-document=/tmp/dns_hosts_dl.txt || true
      fi
      #Does (host file contain a valid nameserver) AND (/etc/resolv.conf doesnt exist OR doesnt match host)
      if grep -qE '^nameserver[[:space:]]+([0-9]{1,3}\.){3}[0-9]{1,3}$' /tmp/dns_hosts_dl.txt && \
      { [[ ! -f /etc/resolv.conf ]] || ! cmp -s /etc/resolv.conf /tmp/dns_hosts_dl.txt; }; then
          cp /tmp/dns_hosts_dl.txt /etc/resolv.conf
      fi
    fi
    sleep 1
  done
fi
