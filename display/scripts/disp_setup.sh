#!/usr/bin/bash
pkill -f "loading_bar.sh" || true
cd /usr/local/bin
oled r
oled +1 "Connect to WiFi"
oled +2 "Name: ExtendFi"
oled +4 "http://10.42.0.1"
oled s
cd -
