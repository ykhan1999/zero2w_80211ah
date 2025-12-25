#!/usr/bin/env bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# ----------- USER CONFIG -------------

#init empty default variables
SSID=""
PASSWORD=""
HSSID=""
HPASSWORD=""
OPTIM=""

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
        --wifi-ssid)
            HSSID="$2"
            shift 2
            ;;
        --wifi-password)
            HPASSWORD="$2"
            shift 2
            ;;
        --optim)
            OPTIM="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--halow-ssid HALOW_SSID_NAME] [--halow-password HALOW_SSID_PASS] [--wifi-ssid NAME] [--wifi-password PASS] [--optim <speed|distance>]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--halow-ssid HALOW_SSID_NAME] [--halow-password HALOW_SSID_PASS] [--wifi-ssid NAME] [--wifi-password PASS] [--optim <speed|distance>]"
            exit 1
            ;;
    esac
done

#prompt user if no input to flags
if [[ -z "$SSID" || -z "$PASSWORD" || -z "$HSSID" || -z "$HPASSWORD" ]]; then
    #prompt user
    read -rp "Enter HaLow SSID: " SSID
    read -rsp "Enter HaLow password: " PASSWORD
    echo ""
    read -rp "Enter 2.4GHz SSID: " HSSID
    read -rsp "Enter 2.4GHz password: " HPASSWORD
    read -rp "Enter optim (<speed|distance>): " OPTIM
fi

if [[ "$OPTIM" != "speed" && "$OPTIM" != "distance" ]]; then
    #error out
    echo "--optim can only be speed or distance"
    exit 1
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
CONFIG_FILE_2=$SCRIPT_DIR/usr_local_bin/80211s_start.sh
sed -i \
    -e "s/ssid=\"[^\"]*\"/ssid=\"$ESCAPED_HSSID\"/" \
    -e "s/psk=\"[^\"]*\"/psk=\"$ESCAPED_HPASS\"/" \
    "$CONFIG_FILE_2"

#Supply the 80211s_stop file with the new hotspot SSID and pw
CONFIG_FILE_3=$SCRIPT_DIR/usr_local_bin/80211s_stop.sh
sed -i \
    -e "s/ssid=\"[^\"]*\"/ssid=\"$ESCAPED_HSSID\"/" \
    -e "s/psk=\"[^\"]*\"/psk=\"$ESCAPED_HPASS\"/" \
    "$CONFIG_FILE_3"

echo "Updated SSID and password in $CONFIG_FILE_2" and "$CONFIG_FILE_3"

#supply halow_80211s.conf with new optimization settings
CONFIG_FILE=$SCRIPT_DIR/config/halow_80211s.conf
if [[ "$OPTIM" == "speed" ]]; then
  sed -i \
    -e "s/channel=\"[^\"]*\"/channel=28/" \
    -e "s/op_class=\"[^\"]*\"/op_class=71/" \
    "$CONFIG_FILE"
fi
if [[ "$OPTIM" == "distance" ]]; then
  sed -i \
    -e "s/channel=\"[^\"]*\"/channel=27/" \
    -e "s/op_class=\"[^\"]*\"/op_class=68/" \
    "$CONFIG_FILE"
fi

echo "Updated channel and bandwidth in $CONFIG_FILE"

# ----------- Install updated config -------------

echo "Installing 80211s_mesh service and script"
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

# keep netman away from wlan1
sudo cp /usr/local/etc/netman_unmanaged.conf.80211s.disabled /etc/NetworkManager/conf.d/unmanaged.conf

# remove default systemd-networkd files
sudo rm -r /etc/systemd/network/99-default.link 2>/dev/null || true

#reload services if running
sudo systemctl daemon-reload

# enable systemd-networkd
sudo systemctl enable --now systemd-networkd

#enable network manager
sudo systemctl enable --now NetworkManager

echo "done updating 80211s_mesh service!"
