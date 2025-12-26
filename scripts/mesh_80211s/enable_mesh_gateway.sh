rm -f /run/boot-mode/lock || true
/usr/local/bin/disable_mesh.sh
sleep 15
systemctl enable 80211s_gateway.service
systemctl start 80211s_gateway.service
