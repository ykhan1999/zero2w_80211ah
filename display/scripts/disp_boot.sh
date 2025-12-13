#!/usr/bin/bash
cd /usr/local/bin
oled r
oled +1 "     EXTEND     "
oled +U 1
oled +3 "Welcome!"
oled +4 "System starting"
oled s
#boot progress
prev_dots=0
while true; do
  dmesg_nlines=$(dmesg | wc -l)
  if [ "$dmesg_nlines" -gt 0 ] && [ "${dots}" != "${prev_dots}" ] ; then
    dots=$(( dmesg_nlines / 30 + 1 ))
    oled +2 "$(printf '%*s' "$dots" '' | tr ' ' '=')"
    oled s
  fi
  prev_dots=${dots}
  sleep 1
done
cd -
