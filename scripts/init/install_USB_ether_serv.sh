#!/usr/bin/bash

#add device tree overlay to config
sudo tee -a /boot/firmware/config.txt >/dev/null <<'EOF'
dtoverlay=dwc2
EOF

#add module to cmdline.txt
sudo sed -i '1{
/modules-load=dwc2,g_ether/! s/$/ modules-load=dwc2,g_ether/
}' /boot/firmware/cmdline.txt

#create systemd service to bring up on start if we can
sudo tee /etc/systemd/system/usb0iface.service >/dev/null <<'EOF'
[Unit]
Description=Bring up usb0
After=systemd-modules-load.service

[Service]
Type=oneshot
ExecStart=/usr/sbin/ip link set up usb0

[Install]
WantedBy=multi-user.target
EOF

#enable service
sudo systemctl enable --now usb0iface.service

#reboot
sudo reboot
