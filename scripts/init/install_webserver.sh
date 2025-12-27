#!/usr/bin/env bash
sudo apt install -y npm

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

#install dnsmasq for redirects
sudo apt update
sudo apt install unbound

#setup DNS redirect config
sudo tee /etc/dnsmasq.d/setup-dns-only.conf >/dev/null <<'EOF'
server:
  interface: 0.0.0.0
  port: 53
  access-control: 0.0.0.0/0 allow

  do-ip4: yes
  do-ip6: no

  # Don't rely on upstream DNS at all
  local-zone: "." redirect
  local-data: ". A 10.42.0.1"
EOF

systemctl restart unbound

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
