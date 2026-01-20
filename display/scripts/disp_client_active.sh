#!/usr/bin/bash
pkill -f "disp_loading_bar.sh" || true
cd /usr/local/bin
oled +2  "NO GATEWAY"
oled +3  "NO INTERNET"
oled s
prev_conn=""
prev_signal=""
prev_internet=""
DEBUG="0"
CONNECTED="NO GATEWAY"

i=15
while true; do
  #get SSID
  SSID=$(iwgetid -r)
  #get signal strength
  Signal=$(sudo iw dev wlan1 station dump | awk '/signal:/ {print $2}')
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
      signalstatus="LOW"
    elif [ "$Signal" -ge "-100" ] && [ "$Signal" -lt "-90" ]; then
      signalstatus="LOW"
    elif [ "$Signal" -lt "-100" ]; then
      sleep 1
      if [ "$Signal" -lt "-100" ]; then
        sleep 1
        if [ "$Signal" -lt "-100" ]; then
        signalstatus="None"
        fi
      fi
    else
      signalstatus="None"
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
  if [ "$CONNECTED" != "$prev_conn" ] || [ "$INTERNET" != "$prev_internet" ] || [ "$signalstatus" != "$prev_signal" ]; then
    oled +3 "$INTERNET"
    oled +4 "Signal: $signalstatus"
    oled +2 "$CONNECTED"
    oled s
  fi
  #store new variables to check for change
  prev_conn="$CONNECTED"
  prev_internet="$INTERNET"
  prev_signal="$signalstatus"
  #loop timer
  sleep 1
  i=$(($i+1))
done
cd -
