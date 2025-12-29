#!/usr/bin/bash
cd /usr/local/bin
oled +2  "NO GATEWAY"
oled +3  "NO INTERNET"
oled s
prev_conn=""
prev_signal=""
prev_internet=""
DEBUG="1"
CONNECTED="NO GATEWAY"

i=15
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
  #get internet and connectivity status
  if [[ "$i" -ge 14 ]]; then
    if ping -c1 -W2 8.8.8.8 &>/dev/null; then
      INTERNET="INTERNET OK"
    else
      INTERNET="NO INTERNET"
    fi
    if ping -c1 -W2 192.160.50.1 &>/dev/null; then
      CONNECTED="GATEWAY OK"
    else
      CONNECTED="NO GATEWAY"
    fi
    i=0
  fi
  #refresh screen only with change
  if [ "$CONNECTED" != "$prev_conn" ] || [ "$signalstatus" != "$prev_signal" ] || [ "$INTERNET" != "$prev_internet" ]; then
    oled +3 "$INTERNET"
    oled +4 "Signal: $signalstatus"
    oled +2 "$CONNECTED"
    oled s
  fi
  #store new variables to check for change
  prev_conn="$CONNECTED"
  prev_signal="$signalstatus"
  prev_internet="$INTERNET"
  #loop timer
  sleep 1
  i=$(($i+1))
done
cd -
