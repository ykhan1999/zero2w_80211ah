#!/usr/bin/env bash

# Default values
MODE=""
WAN=wlan0
LAN=bat0

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
  cp /usr/local/etc/nftables_forward.conf.batman.disabled /etc/nftables.conf
  #restart nftables if active, if inactive then start
  enabled="$(systemctl is-enabled nftables)"
  if [[ "$enabled" != "enabled" ]]; then
     systemctl enable --now nftables
  else
     systemctl restart nftables
  fi
  #Start DHCP server
  cp /usr/local/etc/dnsmasq_DHCP.conf.batman.disabled /etc/dnsmasq.d/lan-$LAN.conf
  systemctl restart dnsmasq
  echo "DHCP server enabled"
  #keep networkmanager away from $LAN
  cp /usr/local/etc/netman_unmanaged.conf.batman.disabled /etc/NetworkManager/conf.d/unmanaged.conf
  systemctl restart NetworkManager
  echo "NAT forwarding ENABLED on ${LAN} -> ${WAN}"

#Turn off NAT forwarding
elif [[ "$MODE" == "off" ]]; then
  echo "Turning OFF all forwarding"
  #apply default nftables ruleset
  cp /usr/local/etc/nftables_noforward.conf.batman.disabled /etc/nftables.conf
  systemctl restart nftables
  #turn off DHCP
  rm -r /etc/dnsmasq.d/lan-$LAN.conf
  systemctl stop dnsmasq
  echo "DHCP server disabled"
  #give network manager control again
  rm -r /etc/NetworkManager/conf.d/unmanaged.conf
  systemctl restart NetworkManager
  echo "NAT forwarding DISABLED for ${LAN}"

else
  echo "Please input a correct command"
fi
