#for gateway
sudo systemctl stop 80211s_gateway.service 2>/dev/null || true
sudo systemctl disable 80211s_gateway.service 2>/dev/null || true
sudo pkill -f "python3 -m http.server" 2>/dev/null || true
#for client
sudo systemctl stop 80211s_client.service 2>/dev/null || true
sudo systemctl disable 80211s_client.service 2>/dev/null || true
