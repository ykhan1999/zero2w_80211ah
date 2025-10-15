#if running as gateway
if grep "active" /usr/local/etc/80211s_gateway_status.txt; then
    sudo systemctl stop 80211s_mesh_gateway.service
    sudo systemctl disable 80211s_mesh_gateway.service
#if client
else
sudo systemctl stop 80211s_mesh_client.service || true
sudo systemctl disable 80211s_mesh_client.service || true
fi
