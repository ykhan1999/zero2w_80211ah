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
        --halow-ssid)
            SSID="$2"
            shift 2
            ;;
        --halow-password)
            PASSWORD="$2"
            shift 2
            ;;
        --hotspot-ssid)
            HSSID="$2"
            shift 2
            ;;
        --hotspot-password)
            HPASSWORD="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--halow-ssid HALOW_SSID_NAME] [--halow-password HALOW_SSID_PASS] [--hotspot-ssid NAME] [--hotspot-password PASS]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--halow-ssid HALOW_SSID_NAME] [--halow-password HALOW_SSID_PASS] [--hotspot-ssid NAME] [--hotspot-password PASS]"
            exit 1
            ;;
    esac
done

#prompt user if no input to flags
if [[ -z "$SSID" || -z "$PASSWORD" || -z "$HSSID" || -z "$HPASSWORD" ]]; then
    #prompt user
    read -rp "Enter HaLow SSID: " SSID
    read -rsp "Enter HaLow password: " PASSWORD
    read -rp "Enter Hotspot SSID: " HSSID
    read -rsp "Enter Hotspot password: " HPASSWORD
fi

# Escape characters that might break sed
ESCAPED_SSID=$(printf '%s\n' "$SSID" | sed 's/[&/\"]/\\&/g')
ESCAPED_PASS=$(printf '%s\n' "$PASSWORD" | sed 's/[&/\"]/\\&/g')
ESCAPED_HSSID=$(printf '%s' "$HSSID" | sed 's/[&/\"]/\\&/g')
ESCAPED_HPASS=$(printf '%s' "$HPASSWORD" | sed 's/[&/\"]/\\&/g')

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
    -e "s/ssid \"[^\"]*\"/ssid \"$ESCAPED_HSSID\"/" \
    -e "s/password \"[^\"]*\"/password \"$ESCAPED_HPASS\"/" \
    "$START_FILE"

echo "Updated hotspot SSID and password in $START_FILE"

# ----------- Install updated config -------------

if [ ! -f "$SERVICE1" ] || [ ! -f "$SERVICE2" ] ; then
  echo "First time setup: Installing 80211s_mesh service and script"
  sudo mkdir -p /usr/local/etc
  # Copy all systemd services
  for f in "$SCRIPT_DIR"/services/*; do
   [ -e "$f" ] || continue
   sudo cp "$f" /etc/systemd/system/
  done

  # Copy all scripts to /usr/local/bin and make them executable
  for f in "$SCRIPT_DIR"/usr_local_bin/*; do
   [ -e "$f" ] || continue
   dest="/usr/local/bin/$(basename "$f")"
   sudo cp "$f" "$dest"
   sudo chmod +x "$dest"
  done

  # Copy all config files to /usr/local/etc
  for f in "$SCRIPT_DIR"/config/*; do
   [ -e "$f" ] || continue
   sudo cp "$f" /usr/local/etc/
  done
  
  sudo rm -r /etc/systemd/network/99-default.link 2>/dev/null
  sudo systemctl daemon-reload
  echo "done installing 80211s_mesh service!"
fi
