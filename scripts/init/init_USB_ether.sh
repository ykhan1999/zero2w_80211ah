#!/usr/bin/bash
#add device tree overlay to config
sudo tee -a /boot/firmware/config.txt >/dev/null <<'EOF'
dtoverlay=dwc2
EOF
#add module to cmdline.txt
sudo sed -i '1{
/modules-load=dwc2,g_ether/! s/$/ modules-load=dwc2,g_ether/
}' /boot/firmware/cmdline.txt
#reboot
sudo reboot
