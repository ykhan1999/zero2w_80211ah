#!/usr/bin/env bash

# Default values
MODE=""
ROLE=""

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
    --gateway)
      ROLE="gateway"
      shift
      ;;
    --client)
      ROLE="client"
      shift
      ;;
    *)
      echo "Unknown argument: $1"
      exit 1
      ;;
  esac
done

# Validate required args
if [[ -z "$MODE" ]]; then
  echo "Usage: $0 --on|--off [--gateway|--client]"
  exit 1
fi

# Ensure only one role is chosen
if [[ "$ROLE" == "gateway" && "$ROLE" == "client" ]]; then
  echo "Error: cannot specify both --gateway and --client"
  exit 1
fi

# Turn on NAT forwarding
if [[ "$MODE" == "on" ]]; then
  
  #for gateway
  if [[ "$ROLE" == "gateway" ]]; then
    #apply nftables ruleset
    cp /usr/local/etc/nftables_forward.conf.80211s.disabled /etc/nftables.conf

    #restart nftables if active, if inactive then start
    enabled="$(systemctl is-enabled nftables)"
    if [[ "$enabled" != "enabled" ]]; then
      systemctl enable --now nftables
    else
      systemctl restart nftables
    fi
  fi

    if [[ "$ROLE" == "client" ]]; then
    #apply nftables ruleset
    cp /usr/local/etc/nftables_forward.client.disabled /etc/nftables.conf

    #restart nftables if active, if inactive then start
    enabled="$(systemctl is-enabled nftables)"
    if [[ "$enabled" != "enabled" ]]; then
      systemctl enable --now nftables
    else
      systemctl restart nftables
    fi
  fi

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
