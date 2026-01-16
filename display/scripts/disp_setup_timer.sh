#!/usr/bin/bash
pkill -f "disp_loading_bar.sh" || true
cd /usr/local/bin
oled +4 "Autostart in $1"
oled s
cd -
