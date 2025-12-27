#run stop script
/usr/local/bin/80211s_stop.sh
#for gateway
systemctl stop 80211s_gateway.service || true
systemctl disable 80211s_gateway.service || true
#for client
systemctl stop 80211s_client.service || true
systemctl disable 80211s_client.service || true
