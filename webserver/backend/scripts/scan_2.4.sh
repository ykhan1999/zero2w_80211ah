#!/usr/bin/env bash
wpa_cli -i wlan0 scan > /dev/null
wpa_cli -i wlan0 scan_results | awk '
NR <= 2 { next }

{
  bssid = $1
  freq = $2
  signal = $3
  flags = $4

  # rebuild SSID (fields 5+)
  ssid = ""
  for (i = 5; i <= NF; i++) {
    ssid = ssid (i == 5 ? "" : " ") $i
  }

  # skip hidden SSIDs
  if (ssid == "") next

  secure = (flags ~ /(WPA|RSN|SAE)/) ? "true" : "false"

  # keep strongest signal per SSID
  if (!(ssid in best_signal) || signal > best_signal[ssid]) {
    best_signal[ssid] = signal
    best_bssid[ssid] = bssid
    best_freq[ssid] = freq
    best_flags[ssid] = flags
    best_secure[ssid] = secure
  }
}

END {
  print "["
  first = 1
  for (s in best_signal) {
    if (!first) print ","
    first = 0

    printf "  {\"ssid\":\"%s\",\"signal\":%d,\"secure\":%s}",
      s,
      best_signal[s],
      best_secure[s]
  }
  print "\n]"
}
'
