#!/usr/bin/bash
pkill -f "disp_loading_bar.sh" || true
cd /usr/local/bin
oled +2 "Starting..."
oled +3 ""
oled +4 ""
oled s
/usr/local/bin/disp_loading_bar.sh 3 > /dev/null 2>&1 &
cd -
