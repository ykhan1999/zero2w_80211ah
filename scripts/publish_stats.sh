# /usr/bin/morse_stats_filtered_pub.sh
#!/bin/sh
set -eu

# ---- CONFIG (override via env or your procd init) ----
MQTT_HOST="${MQTT_HOST:-192.168.4.123}"
MQTT_PORT="${MQTT_PORT:-1883}"
MQTT_USER="${MQTT_USER:-ha_mqtt}"
MQTT_PASS="${MQTT_PASS:-2T2fBYPB0xtddZsC}"
MQTT_TOPIC="${MQTT_TOPIC:-RPI5/HT-HC01P/stats}"

IFACE="${IFACE:-wlan1}"                        # morse_cli interface
MORSE_CLI="${MORSE_CLI:-/usr/bin/morse_cli}"
INTERVAL="${INTERVAL:-5}"                      # seconds
TIMEOUT_SECS="${TIMEOUT_SECS:-3}"              # morse_cli timeout
MQTT_TLS="${MQTT_TLS:-0}"                      # set to 1 to enable TLS
CAFILE="${CAFILE:-/etc/ssl/certs/ca-certificates.crt}"

# Build mosquitto args
MQTT_ARGS="-h $MQTT_HOST -p $MQTT_PORT -t $MQTT_TOPIC -i morse-stats"
[ -n "$MQTT_USER" ] && MQTT_ARGS="$MQTT_ARGS -u $MQTT_USER -P $MQTT_PASS"
[ "$MQTT_TLS" = "1" ] && MQTT_ARGS="$MQTT_ARGS --cafile $CAFILE --tls-version tlsv1.2"

# jq program: pick only the stats we care about, preserving names & nesting
JQ_FILTER='
  def nonull(o): o | to_entries | map(select(.value != null)) | from_entries;

  # Build a minimal object with exactly the keys your HA discovery expects
  . as $root
  | {
      "System uptime (usec)": $root["System uptime (usec)"],
      "Temperature (C)":      $root["Temperature (C)"],
      "Vbat (mV)":            $root["Vbat (mV)"],
      "Current RF frequency (Hz)":        $root["Current RF frequency (Hz)"],
      "Current Operating BW (MHz)":       $root["Current Operating BW (MHz)"],
      "Current Primary Channel BW (MHz)": $root["Current Primary Channel BW (MHz)"],
      "Received power (dBm)": $root["Received power (dBm)"],
      "Noise (dBm)":          $root["Noise (dBm)"],
      "TX Total":             $root["TX Total"],
      "RX total":             $root["RX total"],
      "TX requests":          $root["TX requests"],
      "TX round-trip success (%)": $root["TX round-trip success (%)"],
      "TX ACK timeout":       $root["TX ACK timeout"],
      "TX ACK lost":          $root["TX ACK lost"],
      "RX signal field error": $root["RX signal field error"],
      "Signal field error":    $root["Signal field error"],
      "Packet Detect fired STF": $root["Packet Detect fired STF"],
      "Packet Detect fired LTF": $root["Packet Detect fired LTF"],
      "DCF granted":          $root["DCF granted"],
      "DCF aborted":          $root["DCF aborted"],
      "DCF energy detect fired": $root["DCF energy detect fired"],
      "Beacons TX":           $root["Beacons TX"],
      "Beacons RX":           $root["Beacons RX"],
      "MPE IRQ count":        $root["MPE IRQ count"],
      "RX MPDU delimiters invalid": $root["RX MPDU delimiters invalid"],
      "RX MPDUs with FCS fail":     $root["RX MPDUs with FCS fail"],
      "PHY CPU utilisation (tenths of a percent)": $root["PHY CPU utilisation (tenths of a percent)"],
      "MAC CPU utilisation (tenths of a percent)": $root["MAC CPU utilisation (tenths of a percent)"],
      "Apps CPU utilisation (tenths of a percent)": $root["Apps CPU utilisation (tenths of a percent)"],
      "Narrowband interference count":     $root["Narrowband interference count"],
      "Narrowband interference power (dBm)": $root["Narrowband interference power (dBm)"],
      "MAC state": nonull({
        "RX state": $root["MAC state"]["RX state"],
        "TX state": $root["MAC state"]["TX state"]
      })
    }
  | nonull(.)
'

while :; do
  raw="$(/usr/bin/timeout "$TIMEOUT_SECS" "$MORSE_CLI" -i "$IFACE" stats --json 2>/dev/null || true)"
  case "$raw" in
    \{*)
      # Keep only desired fields (and drop nulls)
      payload="$(printf '%s' "$raw" | jq -c "$JQ_FILTER" 2>/dev/null || true)"
      case "$payload" in
        \{*)
          mosquitto_pub $MQTT_ARGS -q 0 -m "$payload" || logger -t morse_stats "mosquitto_pub failed"
          ;;
        *)
          logger -t morse_stats "jq produced empty/invalid payload"
          ;;
      esac
      ;;
    *)
      logger -t morse_stats "morse_cli returned empty/invalid JSON"
      ;;
  esac
  sleep "$INTERVAL"
done
