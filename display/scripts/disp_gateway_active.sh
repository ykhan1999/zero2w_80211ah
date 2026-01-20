#!/usr/bin/bash
pkill -f "disp_loading_bar.sh" || true
cd /usr/local/bin
oled +2  "NO INTERNET"
oled +3  "NO CLIENTS"
oled s
prev_internet=""
prev_signal=""
prev_peers=""
DEBUG="0"
INTERNET="NO INTERNET"

i=15
while true; do
  #get SSID
  SSID=$(iwgetid -r)
  #get signal strength
  Signal=$(iw dev wlan0 link | awk '/signal:/ {print $2}')
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
  #get number of peers
  Peers=$(journalctl -u 80211s_serve_dns.service --since "2 min ago" | grep -Po "192\\.168\\.50\\.[0-9]+" | sort -u | wc -l)
  #get connectivity state
  if [[ "$i" -ge 14 ]]; then
    if ping -c1 -W2 8.8.8.8 &>/dev/null; then
      INTERNET="INTERNET OK"
    else
      INTERNET="NO INTERNET"
    fi
    i=0
  fi
  #refresh screen only with change
  if [ "$INTERNET" != "$prev_internet" ] || [ "$signalstatus" != "$prev_signal" ] || [ "$Peers" != "$prev_peers" ]; then
    oled +2 "${INTERNET}"
    oled +4 "SIGNAL: $signalstatus"
    oled +3 "CLIENTS: ${Peers}"
    oled s
  fi
  #store new variables to check for change
  prev_internet="$INTERNET"
  prev_signal="$signalstatus"
  prev_peers="$Peers"
  #loop timer
  sleep 1
  i=$(($i+1))
done
cd -
