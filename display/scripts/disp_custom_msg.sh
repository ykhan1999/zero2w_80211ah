#!/usr/bin/bash

line1=""
line2=""
line3=""
line4=""

#parse flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --line1)
            line1="$2"
            shift 2
            ;;
        --line2)
            line2="$2"
            shift 2
            ;;
        --line3)
            line3="$2"
            shift 2
            ;;
        --line4)
            line4="$2"
            shift 2
            ;;
    esac
done

cd /usr/local/bin

if [[ ! -z "$line1" ]]; then
  oled +1 "$line1"
fi

if [[ ! -z "$line2" ]]; then
  oled +2 "$line2"
fi

if [[ ! -z "$line3" ]]; then
  oled +3 "$line3"
fi

if [[ ! -z "$line4" ]]; then
  oled +4 "$line4"
fi


oled s

cd -
