#!/usr/bin/env bash
sudo apt install -y npm

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

cd ${SCRIPT_DIR}/../../webserver/frontend/
npm install
npm run build

cd ${SCRIPT_DIR}/../../webserver/backend/
npm install

sudo cp -r ${SCRIPT_DIR}/../../webserver /usr/local/etc/
sudo cp ${SCRIPT_DIR}/helpers/webserver-backend.service /etc/systemd/system/
sudo cp ${SCRIPT_DIR}/helpers/webserver-frontend.service /etc/systemd/system/
sudo systemctl daemon-reload

sudo cp ${SCRIPT_DIR}/helpers/toggle-webserver.sh /usr/local/bin
sudo chmod +x /usr/local/bin/toggle-webserver.sh

cd -
cd -
