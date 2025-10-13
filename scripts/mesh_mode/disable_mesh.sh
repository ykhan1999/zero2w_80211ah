sudo systemctl stop batman_mesh_gateway.service || true
sudo systemctl stop batman_mesh_client.service || true
sudo systemctl disable batman_mesh_gateway.service || true
sudo systemctl disable batman_mesh_client.service || true
