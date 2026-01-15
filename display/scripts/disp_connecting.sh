#!/usr/bin/bash
pkill -f "loading_bar.sh" || true
cd /usr/local/bin
oled +2 "Starting..."
oled +3 ""
oled +4 ""
oled s
cd -
