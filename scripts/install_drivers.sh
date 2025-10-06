wget https://y3782016.eero.online/packages/hostapd.deb
wget https://y3782016.eero.online/packages/morse_cli.deb
wget https://y3782016.eero.online/packages/wpa_supplicant.deb
sudo apt-get update
sudo apt install -y ./hostapd.deb
sudo apt install -y ./morse_cli.deb
sudo apt install -y ./wpa_supplicant.deb
sudo depmod -a
