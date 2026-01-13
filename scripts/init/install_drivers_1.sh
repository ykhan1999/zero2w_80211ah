#!/usr/bin/env bash
set -euo pipefail

#update package cache
sudo apt-get update

#install dependencies
sudo apt-get install -y libnl-route-3-dev=3.7.0-2
sudo apt-get install -y libnl-3-dev=3.7.0-2
sudo apt-get install -y libnl-genl-3-dev=3.7.0-2
sudo apt-get install -y openssl=3.5.4-1~deb13u1+rpt1

### Download assets
#get latest release
REPO="ykhan1999/zero2w_80211ah"
BASE="https://github.com/ykhan1999/zero2w_80211ah/releases/latest/download"
curl -Ls -o /dev/null -w %{url_effective} "${BASE}" > /tmp/url
URL=$(cat "/tmp/url")

# Download assets from the latest release (filenames must be consistent across releases)
assets=(
  hostapd.deb
  wpa_supplicant.deb
  morse_cli.deb
  morse_firmware.deb
)

for a in "${assets[@]}"; do
  echo "Downloading ${a} from latest release…"
  wget "${URL}/${a}"
done
