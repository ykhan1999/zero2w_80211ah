#!/usr/bin/bash
pkill -f "loading_bar.sh" || true
cd /usr/local/bin
oled +2  "NO GATEWAY"
oled +3  "NO INTERNET"
oled s
prev_conn=""
prev_signal=""
prev_internet=""
DEBUG=""
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
    if [ "$Signal" -ge "-30" ]; then
      signalstatus="********"
    elif [ "$Signal" -ge "-40" ] && [ "$Signal" -lt "-30" ]; then
      signalstatus="*******"
    elif [ "$Signal" -ge "-50" ] && [ "$Signal" -lt "-40" ]; then
      signalstatus="******"
    elif [ "$Signal" -ge "-60" ] && [ "$Signal" -lt "-50" ]; then
      signalstatus="*****"
    elif [ "$Signal" -ge "-70" ] && [ "$Signal" -lt "-60" ]; then
      signalstatus="****"
    elif [ "$Signal" -ge "-80" ] && [ "$Signal" -lt "-70" ]; then
      signalstatus="***"
    elif [ "$Signal" -ge "-90" ] && [ "$Signal" -lt "-80" ]; then
      signalstatus="**"
    elif [ "$Signal" -ge "-100" ] && [ "$Signal" -lt "-90" ]; then
      signalstatus="*"
    elif [ "$Signal" -lt "-100" ]; then
      sleep 1
      if [ "$Signal" -lt "-100" ]; then
        sleep 1
        if [ "$Signal" -lt "-100" ]; then
        signalstatus="None"
        fi
      fi
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
