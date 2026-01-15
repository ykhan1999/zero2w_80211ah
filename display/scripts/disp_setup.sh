#!/usr/bin/bash
pkill -f "loading_bar.sh" || true
cd /usr/local/bin
oled r
oled +1 "To setup:"
oled +2 "WiFi 'ExtendFi'"
oled +3 "Then 10.42.0.1"
oled s
cd -
