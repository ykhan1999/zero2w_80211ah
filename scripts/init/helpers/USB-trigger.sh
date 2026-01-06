#!/usr/bin/env bash

#bring up usb tethering
/usr/bin/nmcli con up usb0-host || true