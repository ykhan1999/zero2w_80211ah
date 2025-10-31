#!/usr/bin/env bash

# Default values
MODE=""
WAN=wlan1
LAN=wlan0

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
  cp /usr/local/etc/nftables_forward.conf.80211ac.disabled /etc/nftables.conf

  #restart nftables if active, if inactive then start
  enabled="$(systemctl is-enabled nftables)"
  if [[ "$enabled" != "enabled" ]]; then
     systemctl enable --now nftables
  else
     systemctl restart nftables
  fi

  echo "NAT forwarding ENABLED on ${LAN} -> ${WAN}"

#Turn off NAT forwarding
elif [[ "$MODE" == "off" ]]; then
  echo "Turning OFF all forwarding"
  #apply default nftables ruleset
  cp /usr/local/etc/nftables_noforward.conf.80211s.disabled /etc/nftables.conf
  systemctl restart nftables
  echo "NAT forwarding DISABLED for ${LAN}"

else
  echo "Please input a correct command"
fi
