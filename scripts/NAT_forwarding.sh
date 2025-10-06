# Set interface vars
WAN="wlan0"     # uplink (2.4Ghz)
LAN="wlan1"     # internal side (HaLow)

# 1) Enable IPv4 forwarding (now + persist)
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-ipforward.conf
sudo sysctl --system

# 2) nftables filter + NAT (MASQUERADE out $WAN)
sudo tee /etc/nftables.conf >/dev/null <<'EOF'
flush ruleset
define wan = "wlan0"
define lan = "wlan1"

table inet filter {
  chain input   { type filter hook input priority 0; policy accept; }
  chain output  { type filter hook output priority 0; policy accept; }
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    iifname $lan oifname $wan accept
  }
}
table ip nat {
  chain postrouting {
    type nat hook postrouting priority 100;
    oifname $wan masquerade
  }
}
EOF

sudo systemctl enable --now nftables

# 3) dhcp server
sudo apt-get update && sudo apt-get install -y dnsmasq
sudo tee /etc/dnsmasq.d/lan-$LAN.conf >/dev/null <<EOF
interface=$LAN
bind-interfaces
dhcp-range=192.168.50.50,192.168.50.200,255.255.255.0,12h
dhcp-option=option:router,192.168.50.1
dhcp-option=option:dns-server,192.168.50.1
EOF
sudo systemctl restart dnsmasq

# 4) keep NetMan away from wlan1
sudo tee /etc/NetworkManager/conf.d/unmanaged.conf >/dev/null <<EOF
[keyfile]
unmanaged-devices=interface-name:$LAN
EOF
sudo systemctl restart NetworkManager
