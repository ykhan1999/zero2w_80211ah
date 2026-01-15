#!/usr/bin/bash
pkill -f "loading_bar.sh" || true
cd /usr/local/bin
oled +4 "Autostart in $1"
oled s
cd -
