rm -f /run/boot-mode/lock || true
systemctl enable 80211s_gateway.service
systemctl start 80211s_gateway.service
