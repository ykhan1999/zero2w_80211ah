#!/usr/bin/bash
cd /usr/local/bin
oled +2  "ACTIVE | NO CLIENTS"
oled s
previous_ssid=""
previous_signal=""
prev_peers=""
DEBUG="1"

while true; do
  #get SSID
  SSID=$(iwgetid -r)
  #get signal strength
  Signal=$(morse_cli -i wlan1 stats | grep Received | grep -Po '\-[[:digit:]]+')
  if [ "$DEBUG" -eq "1" ]; then
    signalstatus="$Signal"
  else
    if [ "$Signal" -gt "-40" ]; then
      signalstatus="Strong"
    elif [ "$Signal" -gt "-80" ] && [ "$Signal" -lt "-39" ]; then
      signalstatus="Moderate"
    elif [ "$Signal" -gt "-100" ] && [ "$Signal" -lt "-79" ]; then
      signalstatus="Weak"
    elif [ "$Signal" -lt "-100" ]; then
      signalstatus="None"
    else
      signalstatus="$Signal"
    fi
  fi
  #get number of peers
  Peers=$(journalctl -u 80211s_serve_dns.service | tail -n 10 | grep -Po "192\\.168\\.50\\.[0-9]+" | sort -u | wc -l)
  #refresh screen only with change
  if [ "$SSID" != "$prev_ssid" ] || [ "$signalstatus" != "$prev_signal" ] || [ "$Peers" != "$prev_peers" ]; then
    oled +3 "SSID: $SSID"
    oled +4 "Signal: $signalstatus"
    oled +2 "CLIENTS: ${Peers}"
    oled s
  fi
  #store new variables to check for change
  prev_ssid="$SSID"
  prev_signal="$signalstatus"
  prev_peers="$Peers"
  #loop timer
  sleep 1
done
cd -
