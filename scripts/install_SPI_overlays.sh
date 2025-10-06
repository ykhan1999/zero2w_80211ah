#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

#Install device tree overlays
sudo apt-get update
sudo apt-get install device-tree-compiler
dtc -@ -I dts -O dtb -o $SCRIPT_DIR/../overlays/morse-spi.dtbo $SCRIPT_DIR/../overlays/morse-spi.dts
dtc -@ -I dts -O dtb -o $SCRIPT_DIR/../overlays/mm-wlan.dtbo $SCRIPT_DIR/../overlays/mm-wlan.dts
sudo cp $SCRIPT_DIR/../overlays/*.dtbo /boot/firmware/overlays/

####Patch morse driver to reset module until it's recognized

#Don't autostart morse
sudo cp $SCRIPT_DIR/helpers/morse.conf.SPI.patch /etc/modprobe.d/morse.conf

#service to reset until driver is recognized
sudo cp $SCRIPT_DIR/helpers/start_morse.service.SPI.patch /etc/systemd/system/start_morse.service
mkdir -p /usr/local/bin/
sudo cp $SCRIPT_DIR/helpers/start_morse.sh.SPI.patch /usr/local/bin/start_morse.sh
sudo chmod +x /usr/local/bin/start_morse.sh
sudo systemctl enable start_morse

#reboot to apply
sudo reboot
