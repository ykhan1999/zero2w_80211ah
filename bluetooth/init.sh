#!/usr/bin/bash

##to build from source
#sudo apt install -y git
#sudo git clone https://github.com/petzval/btferret.git
#sudo apt install -y python3-setuptools
#sudo apt install -y python3-dev
#cd btferret
#sudo python3 btfpymake.py build
#cp -r build/lib.linux-aarch64-cpython-313/* ..
#cd ..

sudo cp services/ble_server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ble_server
