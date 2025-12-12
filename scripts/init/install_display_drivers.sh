#!/usr/bin/bash

### Download assets
#get latest release
REPO="ykhan1999/zero2w_80211ah"
BASE="https://github.com/ykhan1999/zero2w_80211ah/releases/latest/download"
curl -Ls -o /dev/null -w %{url_effective} "${BASE}" > /tmp/url
URL=$(cat "/tmp/url")

# Download assets from the latest release (filenames must be consistent across releases)
assets=(
  wiringpi.deb
)

# install assets
for a in "${assets[@]}"; do
  echo "Downloading ${a} from latest release…"
  wget "${URL}/${a}"
done

sudo apt-get update
for a in "${assets[@]}"; do
  echo "Installing ${a} from latest release…"
  sudo apt install -y ./${a}
done

#add parameters to boot config file for display
sudo echo "dtoverlay=i2c0" >> /boot/firmware/config.txt
sudo echo "dtparam=i2c_arm=on" >> /boot/firmware/config.txt

#copy over binaries to control display
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

sudo cp -r ${SCRIPT_DIR}/../../display/fontx /usr/local/bin
sudo cp ${SCRIPT_DIR}/../../display/scripts/* /usr/local/bin
sudo chmod +x /usr/local/bin/disp*
sudo reboot
