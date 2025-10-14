#if running as gateway
if grep "active" /usr/local/etc/batman_gateway_status.txt; then
    sudo systemctl stop batman_mesh_gateway.service
    sudo systemctl disable batman_mesh_gateway.service
#if client
else
sudo systemctl stop batman_mesh_client.service || true
sudo systemctl disable batman_mesh_client.service || true
fi
#just for good measure, run the batman stop script again
sudo /usr/local/bin/batman_stop.sh
