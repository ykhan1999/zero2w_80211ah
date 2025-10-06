wget https://github.com/ykhan1999/zero2w_80211ah/releases/download/main/hostapd.deb
wget https://github.com/ykhan1999/zero2w_80211ah/releases/download/main/morse_cli.deb
wget https://github.com/ykhan1999/zero2w_80211ah/releases/download/main/wpa_supplicant.deb
wget https://github.com/ykhan1999/zero2w_80211ah/releases/download/main/morse_firmware.deb
sudo apt-get update
sudo apt install -y ./hostapd.deb
sudo apt install -y ./morse_cli.deb
sudo apt install -y ./wpa_supplicant.deb
sudo apt install -y ./morse_firmware.deb
sudo depmod -a
