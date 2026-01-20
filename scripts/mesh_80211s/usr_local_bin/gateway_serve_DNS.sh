#!/usr/bin/env bash

WAN_IF="wlan0"          # upstream interface on Node B
LAN_IF="wlan1"          # LAN interface facing Node A
OUTDIR="/srv/nodeA_dns"
OUTFILE="$OUTDIR/nameservers.conf"
PORT=8080
LAN_IP="192.168.50.1"

mkdir -p "$OUTDIR"

# 1) Read upstream DNS from NetworkManager on WAN
mapfile -t DSN < <(nmcli -t -f IP4.DNS device show "$WAN_IF" | cut -d: -f2 | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)

# Fallback: try NM's internal resolv file, if present
if [ ${#DSN[@]} -eq 0 ] && [ -f /var/run/NetworkManager/resolv.conf ]; then
  mapfile -t DSN < <(grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' /var/run/NetworkManager/resolv.conf || true)
fi

# 2) Write them in resolv.conf format
{
  for d in "${DSN[@]}"; do
    echo "nameserver $d"
  done
} > "$OUTFILE"

if [ ${#DSN[@]} -eq 0 ]; then
    echo "nameserver 8.8.8.8" > "$OUTFILE"
fi
echo "Wrote $(wc -l < "$OUTFILE") DNS server(s) to $OUTFILE:"
cat "$OUTFILE"

# Kill any previous server on this port
pkill -f "python3 -m http.server $PORT" 2>/dev/null || true

# Start HTTP server bound to wlan1 IP in background
python3 -m http.server "$PORT" --bind "${LAN_IP}" --directory "$OUTDIR"

echo "Serving $OUTFILE at: http://$LAN_IP:$PORT/$(basename "$OUTFILE")"
