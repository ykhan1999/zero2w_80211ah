#!/usr/bin/env bash

# Default values
MODE=""
WAN=wlan0
LAN=wlan1

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --on)
      MODE="on"
      shift
      ;;
    --off)
      MODE="off"
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
  echo "Usage: $0 --on|--off"
  exit 1
fi

# Turn on NAT forwarding
if [[ "$MODE" == "on" ]]; then
  echo "Turning ON forwarding with WAN=$WAN and LAN=$LAN"
  #apply nftables ruleset
  sudo cp /usr/local/etc/nftables_forward.conf.disabled /etc/nftables.conf
  #restart nftables if active, if inactive then start
  enabled="$(systemctl is-enabled nftables)"
  if [[ "$enabled" != "enabled" ]]; then
     sudo systemctl enable --now nftables
  else
     sudo systemctl restart nftables
  fi
  #Start DHCP server
  sudo cp /usr/local/etc/dnsmasq_DHCP.conf.disabled /etc/dnsmasq.d/lan-$LAN.conf
  sudo systemctl restart dnsmasq
  echo "DHCP server enabled"
  #keep networkmanager away from $LAN
  sudo cp /usr/local/etc/netman_unmanaged.conf.disabled /etc/NetworkManager/conf.d/unmanaged.conf
  sudo systemctl restart NetworkManager
  echo "NAT forwarding ENABLED on ${LAN} -> ${WAN}"

#Turn off NAT forwarding
elif [[ "$MODE" == "off" ]]; then
  echo "Turning OFF all forwarding"
  #apply default nftables ruleset
  sudo cp /usr/local/etc/nftables_noforward.conf.disabled /etc/nftables.conf
  sudo systemctl restart nftables
  #turn off DHCP
  sudo rm -r /etc/dnsmasq.d/lan-$LAN.conf
  sudo systemctl stop dnsmasq
  echo "DHCP server disabled"
  #give network manager control again
  sudo rm -r /etc/NetworkManager/conf.d/unmanaged.conf
  sudo systemctl restart NetworkManager
  echo "NAT forwarding DISABLED for ${LAN}"

else
  echo "Please input a correct command"
fi
