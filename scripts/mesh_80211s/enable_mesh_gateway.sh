sudo rm -f /run/boot-mode/lock || true
sudo systemctl enable --now 80211s_gateway.service
