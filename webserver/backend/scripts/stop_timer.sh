#!/usr/bin/bash
pkill -f "boot-mode-switch.sh" || true
pkill -f 'disp_setup_timer.sh" || true
disp_custom_msg.sh --line4 "Configuring..."
