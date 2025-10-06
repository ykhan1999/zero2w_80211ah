#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

sudo apt-get update
sudo apt-get install device-tree-compiler
dtc -@ -I dts -O dtb -o $SCRIPT_DIR/../overlays/morse-spi.dtbo $SCRIPT_DIR/../overlays/morse-spi.dts
dtc -@ -I dts -O dtb -o $SCRIPT_DIR/../overlays/mm-wlan.dtbo $SCRIPT_DIR/../overlays/mm-wlan.dts
sudo cp $SCRIPT_DIR/../overlays/*.dtbo /boot/firmware/overlays/
sudo reboot
