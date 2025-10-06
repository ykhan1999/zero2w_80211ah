#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

#start hostapd on boot with sample config file
sudo cp $SCRIPT_DIR/helpers/start_hostapd.service /etc/systemd/system/
sudo cp $SCRIPT_DIR/helpers/start_hostapd.sh /usr/local/bin/
sudo cp $SCRIPT_DIR/../sample_configs/hostapd.conf /usr/local/bin/hostapd.conf
sudo chmod +x /usr/local/bin/start_hostapd.sh
sudo systemctl enable start_hostapd

#assign static IP
sudo cp $SCRIPT_DIR/helpers/static_ip.service /etc/systemd/system/
sudo cp $SCRIPT_DIR/helpers/assign_wlan1_ip.sh /usr/local/bin
sudo chmod +x /usr/local/bin/assign_wlan1_ip.sh
sudo systemctl enable static_ip.service

