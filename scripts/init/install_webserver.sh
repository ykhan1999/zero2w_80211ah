#!/usr/bin/env bash
sudo apt-cache update
sudo apt install -y npm=9.2.0~ds1-3

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

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

#shorten boot time
sudo systemctl disable NetworkManager-wait-online.service

cd -
cd -
