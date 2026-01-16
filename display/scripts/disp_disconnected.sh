#!/usr/bin/bash
pkill -f "disp_loading_bar.sh" || true
cd /usr/local/bin
oled +2 "DISCONNECTED"
oled +3 ""
oled +4 ""
oled s
cd -
