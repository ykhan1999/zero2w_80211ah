#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 {on|off}"
  exit 1
fi

case "$1" in
  on)
    echo "Turning ON webserver"
    systemctl enable --now webserver-backend.service
    systemctl enable --now webserver-frontend.service
    ;;
  off)
    echo "Turning OFF webserver"
    systemctl stop webserver-backend.service
    systemctl stop webserver-frontend.service
    systemctl disable webserver-backend.service
    systemctl disable webserver-frontend.service

    ;;
  *)
    echo "Invalid argument: $1"
    echo "Usage: $0 {on|off}"
    exit 1
    ;;
esac

