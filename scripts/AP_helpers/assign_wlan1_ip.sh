#!/usr/bin/env bash
ip addr flush dev wlan1
ip addr add 192.168.50.1/24 dev wlan1
ip link set wlan1 up
