#!/usr/bin/bash
pkill -f "disp_loading_bar.sh" || true
cd /usr/local/bin
oled r
oled +1 "  Client Mode   "
oled +U 1
oled s
cd -
