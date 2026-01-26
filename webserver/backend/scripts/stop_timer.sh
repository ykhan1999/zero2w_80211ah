#!/usr/bin/bash
pkill -f "boot-mode-switch.sh"
pkill -f 'disp_setup_timer.sh"
disp_custom_msg.sh --line4 "Timer stopped"
