#!/usr/bin/env bash
set -euo pipefail
git clone https://github.com/MorseMicro/rpi-linux -b mm/rpi-6.6.31/1.15.x --single-branch
cd rpi-linux
export ARCH=arm64
export KERNEL=kernel8
export O=$PWD/../build-zero2w-aarch64
mkdir -p "$O"
make O="$O" bcm2711_defconfig
make -j1 O="$O" Image modules dtbs > "$O"/build.log
sudo make O="$O" modules_install
sudo cp "$O/arch/arm64/boot/Image" /boot/firmware/$KERNEL.img
sudo cp "$O/arch/arm64/boot/dts/broadcom/"*.dtb /boot/firmware/
sudo cp "$O/arch/arm64/boot/dts/overlays/"*.dtb* /boot/firmware/overlays/

