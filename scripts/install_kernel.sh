sudo mkdir -p /tmp/rpi-fix/
wget https://github.com/ykhan1999/zero2w_80211ah/releases/download/main/rpilinux-zero2w_1.0-2.deb
sudo dpkg -x rpilinux-zero2w_1.0-2.deb /tmp/rpi-fix/
sudo cp /tmp/rpi-fix/boot/firmware/*.dtb /boot/firmware/
sudo cp /tmp/rpi-fix/boot/firmware/config.txt /boot/firmware/config.txt
sudo cp /tmp/rpi-fix/boot/firmware/kernel8.img /boot/firmware/
sudo cp /tmp/rpi-fix/boot/firmware/overlays/* /boot/firmware/overlays/
sudo cp -r /tmp/rpi-fix/lib/modules/6.12.21-v8 /lib/modules/6.12.21-v8
sudo depmod -a "6.12.21-v8"
reboot
