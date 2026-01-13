#!/usr/bin/env bash
set -euo pipefail

#update package cache
sudo apt-get update

# Install assets from the latest release (filenames must be consistent across releases)
assets=(
  hostapd.deb
  wpa_supplicant.deb
  morse_cli.deb
  morse_firmware.deb
)

for a in "${assets[@]}"; do
  echo "Installing ${a} from latest release…"
  sudo apt install -y ./${a}
done

sudo depmod -a
