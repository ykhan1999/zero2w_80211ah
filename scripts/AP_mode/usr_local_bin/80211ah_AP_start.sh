#!/usr/bin/env bash

#restart driver module for fresh bringup
systemctl stop start_morse
modprobe -r morse
systemctl restart start_morse
echo "Driver module restarted"

#static IP for wlan1
ip addr flush dev wlan1
ip addr add 192.168.50.1/24 dev wlan1
ip link set wlan1 up

#enable NAT forward and DHCP server for wlan1
/usr/local/bin/toggle_NAT.sh --on

#only proceed if dnsmasq starts successfully

SERVICE="dnsmasq.service"
TIMEOUT=60

echo "Waiting for $SERVICE to exit successfully..."

while true; do
  STATE=$(systemctl show -p ActiveState --value "$SERVICE")

  if [[ "$STATE" == "active" ]]; then
    echo "[+] $SERVICE is active!"
    break
  elif [[ "$STATE" == "failed" ]]; then
    echo "[!] $SERVICE failed to start."
    exit 1
  fi
done

#bring up AP, but only proceed if enables successfully, otherwise keep retrying
while true; do

    echo "STARTING AP..."
    sleep 10
    hostapd_s1g -t /usr/local/etc/hostapd.conf > /usr/local/etc/hostapd.log 2>&1 &
    HAPD_PID=$!
    renice -20 $HAPD_PID

    TRIGGER_ON="AP-ENABLED"
    TRIGGER_OFF="failed"

    #monitor log for success/fail
    sleep 1
    while read -r line; do

        echo "$line"

        #if startup successful
        if [[ "$line" == *"$TRIGGER_ON"* ]]; then
            echo "AP successfully started"
            #exit with success
            break 2

        #if unsuccessful, retry
        elif [[ "$line" == *"$TRIGGER_OFF"* ]]; then
            echo "AP startup unsuccesful, retrying..."
            kill $HAPD_PID
            wait $HAPD_PID
            sleep
            break

         fi

    done < <(tail -f -n +1 /usr/local/etc/hostapd.log)

done

#set static IP for wlan1 (again)
ip addr flush dev wlan1
ip addr add 192.168.50.1/24 dev wlan1
ip link set wlan1 up

#watchdog
TRIGGER_OFF="AP-DISABLED"
while IFS= read -r line || [ -n "$line" ]; do
    if [[ "$line" == *"$TRIGGER_OFF"* ]]; then
        systemctl restart 80211ah_AP
        exit 1
    fi
done < <(tail -f -n +1 /usr/local/etc/hostapd.log)
