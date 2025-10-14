#!/usr/bin/env bash
set -euo pipefail

### Download assets
#get latest release
REPO="ykhan1999/zero2w_80211ah"
BASE="https://github.com/ykhan1999/zero2w_80211ah/releases/latest/download"
curl -Ls -o /dev/null -w %{url_effective} "${BASE}" > /tmp/url
URL=$(cat "/tmp/url")

# Download assets from the latest release (filenames must be consistent across releases)
assets=(
  hostapd.deb
  morse_cli.deb
  morse_firmware.deb
)

for a in "${assets[@]}"; do
  echo "Downloading ${a} from latest release…"
  wget "${URL}/${a}"
done

sudo apt-get update
for a in "${assets[@]}"; do
  echo "Installing ${a} from latest release…"
  sudo apt install -y ./${a}
done

#for some reason, wpa_supplicant_s1g doesn't play nice with package manager

assets=(
  wpa_supplicant.deb
)

for a in "${assets[@]}"; do
  echo "Downloading ${a} from latest release…"
  wget "${URL}/${a}"
done

sudo apt-get update
for a in "${assets[@]}"; do
  echo "Installing ${a} from latest release…"
  sudo dpkg -i ./${a}
done

sudo depmod -a
