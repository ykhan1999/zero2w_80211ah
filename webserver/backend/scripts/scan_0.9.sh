#!/usr/bin/env bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
PW=$(cat /dev/urandom | tr -dc A-Za-z0-9 | head -c 50)

sed -i \
  -e "s/sae_password=\"[^\"]*\"/sae_password=\"${PW}\"/" \
  "${SCRIPT_DIR}/dummy.conf"

wpa_supplicant_s1g -i wlan1 -c ${SCRIPT_DIR}/dummy.conf -B > /dev/null
sleep 3
wpa_cli_s1g -i wlan1 scan > /dev/null
wpa_cli_s1g -i wlan1 scan_results | awk -F'\t' '
BEGIN { print "[" }
NR>1 && $5 != "" {
  printf("%s{\"ssid\":\"%s\",\"signal\":%s,\"secure\":true}", (n++?",":""), $5, $3)
}
END { print "]" }
'

pkill -f "wpa_supplicant_s1g -i wlan1 -c ${SCRIPT_DIR}/dummy.conf -B" > /dev/null
