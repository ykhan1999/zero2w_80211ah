#!/usr/bin/env bash

#helper to get current dir

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# ----------- FIRST TIME CONFIG -------------

#1. Is python3 installed?
PKG="python3"

if ! dpkg -s "$PKG" >/dev/null 2>&1; then
  echo "First time setup: installing $PKG now..."
  sudo apt-get update -y
  sudo apt-get install -y "$PKG"
  echo "$PKG installed!"
fi

#2. Is dhclient installed?
PKG="isc-dhcp-client"

if ! dpkg -s "$PKG" >/dev/null 2>&1; then
  echo "First time setup: installing $PKG now..."
  sudo apt-get update -y
  sudo apt-get install -y "$PKG"
  echo "$PKG installed!"
fi

#3. Is IPv4 forwarding enabled at the kernel level?

CONF="/etc/sysctl.d/99-ipforward.conf"
LINE="net.ipv4.ip_forward=1"

if [ ! -f "$CONF" ] || ! grep -qx "$LINE" "$CONF"; then
  echo "First time setup: Enable ipv4 forward at kernel level..."
  sudo rm -f "$CONF"
  echo "$LINE" | sudo tee "$CONF" >/dev/null
  sudo sysctl --system >/dev/null
  echo "ipv4 forwarding capability enabled!"
fi

#4. Is NetMan being kept from wlan1?

CONF="/etc/NetworkManager/conf.d/unmanaged.conf"
LINE="unmanaged-devices=interface-name:wlan1"

# create conf file if missing or corrupt
if [ ! -f "$CONF" ] || ! grep -qx "$LINE" "$CONF"; then
  echo "Keeping NetworkManager away from wlan1"
  sudo cp /usr/local/etc/netman_unmanaged.conf.80211s.disabled $CONF
  sudo systemctl restart NetworkManager
fi

# ----------- USER CONFIG -------------

#init empty default variables
SSID=""
PASSWORD=""
HSSID=""
HPASSWORD=""

#parse flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ssid)
            SSID="$2"
            shift 2
            ;;
        --password)
            PASSWORD="$2"
            shift 2
            ;;
        --halow-ssid)
            HSSID="$2"
            shift 2
            ;;
        --halow-password)
            HPASSWORD="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--ssid NAME] [--password PASS] [--halow-ssid NAME] [--halow-password PASS]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

#prompt user
read -rp "Enter HaLow SSID: " SSID
read -rsp "Enter HaLow password: " PASSWORD
read -rp "Enter Hotspot SSID: " HSSID
read -rsp "Enter Hotspot password: " HPASSWORD

#ensure there is input
if [[ -z "$SSID" || -z "$PASSWORD" || -z "$HSSID" || -z "$HPASSWORD" ]]; then
    echo "Error: SSID and password cannot be empty."
    exit 1
fi

# Escape characters that might break sed
ESCAPED_SSID=$(printf '%s\n' "$SSID" | sed 's/[&/\"]/\\&/g')
ESCAPED_PASS=$(printf '%s\n' "$PASS" | sed 's/[&/\"]/\\&/g')
ESCAPED_HSSID=$(printf '%s' "$HSSID" | sed 's/[&/\"]/\\&/g')
ESCAPED_HPASS=$(printf '%s' "$HPASS" | sed 's/[&/\"]/\\&/g')

# Supply the config file with the new HaLow SSID and pw
CONFIG_FILE=$SCRIPT_DIR/config/halow_80211s.conf
sed -i \
    -e "s/ssid=\"[^\"]*\"/ssid=\"$ESCAPED_SSID\"/" \
    -e "s/sae_password=\"[^\"]*\"/sae_password=\"$ESCAPED_PASS\"/" \
    "$CONFIG_FILE"

echo "Updated SSID and password in $CONFIG_FILE"

#Supply the 80211s_start file with the new hotspot SSID and pw
START_FILE=$SCRIPT_DIR/usr_local_bin/80211s_start.sh
sed -i \
    -e "s/ssid [^ ]*/ssid $ESCAPED_HSSID/" \
    -e "s/password \"[^\"]*\"/password \"$ESCAPED_HPASS\"/" \
    "$START_FILE"

echo "Updated hotspot SSID and password in $START_FILE"

# ----------- Install updated config -------------

if [ ! -f "$SERVICE1" ] || [ ! -f "$SERVICE2" ] ; then
  echo "First time setup: Installing 80211s_mesh service and script"
  sudo mkdir -p /usr/local/etc
  sudo cp $SCRIPT_DIR/services/80211s_gateway.service /etc/systemd/system/
  sudo cp $SCRIPT_DIR/services/80211s_client.service /etc/systemd/system/
  sudo cp $SCRIPT_DIR/services/80211s_serve_dns.service /etc/systemd/system/
  sudo cp $SCRIPT_DIR/usr_local_bin/80211s_start.sh /usr/local/bin/
  sudo cp $SCRIPT_DIR/usr_local_bin/80211s_stop.sh /usr/local/bin/
  sudo cp $SCRIPT_DIR/usr_local_bin/toggle_NAT_80211s.sh /usr/local/bin/
  sudo cp $SCRIPT_DIR/usr_local_bin/gateway_serve_DNS.sh /usr/local/bin/
  sudo cp $SCRIPT_DIR/config/halow_80211s.conf /usr/local/etc/
  sudo cp $SCRIPT_DIR/config/netman_unmanaged.conf.80211s.disabled /usr/local/etc/
  sudo cp $SCRIPT_DIR/config/nftables_forward.conf.80211s.disabled /usr/local/etc/
  sudo cp $SCRIPT_DIR/config/nftables_noforward.conf.80211s.disabled /usr/local/etc/
  sudo cp $SCRIPT_DIR/config/10-wlan1.network.80211s.disabled /usr/local/etc/
  sudo chmod +x /usr/local/bin/80211s_start.sh
  sudo chmod +x /usr/local/bin/80211s_stop.sh
  sudo chmod +x /usr/local/bin/toggle_NAT_80211s.sh
  sudo chmod +x /usr/local/bin/gateway_serve_DNS.sh
  sudo rm -r /etc/systemd/network/99-default.link 2>/dev/null
  sudo systemctl daemon-reload
  echo "done installing 80211s_mesh service!"
fi
