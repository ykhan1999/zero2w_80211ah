#!/usr/bin/bash
cd /usr/local/bin
oled +2  "CONNECTED"
previous_ssid=""
previous_signal=""

while true; do
  #get SSID
  SSID=$(iwgetid -r)
  #get signal strength
  Signal=$(morse_cli -i wlan1 stats | grep Received | grep -Po '\-[[:digit:]]+')
  if [ "$Signal" -gt "-40" ]; then
    signalstatus="Strong"
  elif [ "$Signal" -gt "-80" ] && [ "$Signal" -lt "-39" ]; then
    signalstatus="Moderate"
  elif [ "$Signal" -lt "-79" ]; then
    signalstatus="Weak"
  else
    signalstatus="$Signal"
  fi
  #refresh screen only with change
  if [ "$SSID" != "$prev_ssid" ] || [ "$signalstatus" != "$prev_signal" ]; then
    oled +3 "SSID: $SSID"
    oled +4 "Signal: $signalstatus"
    oled s
  fi
  #store new variables to check for change
  prev_ssid="$SSID"
  prev_signal="$signalstatus"
  #loop timer
  sleep 1
done
cd -
