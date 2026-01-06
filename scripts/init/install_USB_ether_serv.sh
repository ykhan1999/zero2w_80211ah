#!/usr/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

#add device tree overlay to config
sudo tee -a /boot/firmware/config.txt >/dev/null <<'EOF'
dtoverlay=dwc2
EOF

#add module to cmdline.txt
sudo sed -i '1{
/modules-load=dwc2,g_ether/! s/$/ modules-load=dwc2,g_ether/
}' /boot/firmware/cmdline.txt

#enable shared connection through NetworkManager for clients
nmcli connection add \
    type ethernet \
    ifname usb0 \
    con-name usb0-host \
    autoconnect yes

#bring up connection now if possible
nmcli con up usb0-host || true

#add udev rule to try to bring up the connection when any usb device connects
sudo cp ${SCRIPT_DIR}/helpers/USB-trigger.sh /usr/local/bin/USB-trigger.sh
sudo chmod +x /usr/local/bin/USB-trigger.sh
sudo cp ${SCRIPT_DIR}/helpers/99-usb-connect.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger

#reboot to apply changes
sudo reboot