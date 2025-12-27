#!/usr/bin/env bash
sudo apt install -y npm

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

#install dnsmasq for redirects
sudo apt update
sudo apt install dnsmasq

#disable global config
sudo systemctl stop dnsmasq
sudo systemctl disable dnsmasq

#setup DNS redirect config
sudo tee /etc/dnsmasq.d/setup-dns-only.conf >/dev/null <<'EOF'
# DNS only (no DHCP)
port=53
no-dhcp-interface=wlan0

# Bind only on the AP interface + IP
interface=wlan0
bind-interfaces

# Don't use /etc/hosts or upstream resolv.conf
no-hosts
no-resolv

# ONLY redirect this hostname
address=/setup.com/10.42.0.1
address=/www.setup.com/10.42.0.1
EOF

#install node.js files
cd ${SCRIPT_DIR}/../../webserver/frontend/
npm install
npm run build

cd ${SCRIPT_DIR}/../../webserver/backend/
npm install

#copy files to system directory
sudo cp -r ${SCRIPT_DIR}/../../webserver /usr/local/etc/
sudo cp ${SCRIPT_DIR}/helpers/webserver-backend.service /etc/systemd/system/
sudo cp ${SCRIPT_DIR}/helpers/webserver-frontend.service /etc/systemd/system/

sudo cp ${SCRIPT_DIR}/helpers/boot-mode-switch.sh /usr/local/bin
sudo chmod +x /usr/local/bin/boot-mode-switch.sh

sudo cp ${SCRIPT_DIR}/helpers/boot-mode-switch.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now boot-mode-switch.service

#bring down preconfigured wifi if flashed using rpi imager
sudo nmcli con down preconfigured || true
sudo nmcli con delete preconfigured || true

#copy entire repo to system directly to correctly reference config files
sudo mkdir -p /usr/local/etc/zero2w_80211ah
sudo cp -r ${SCRIPT_DIR}/../../* /usr/local/etc/zero2w_80211ah

cd -
cd -
