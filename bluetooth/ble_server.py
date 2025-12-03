#!/usr/bin/python3
import subprocess
import btfpy

def le_callback(clientnode, operation, cticn):
    if operation == btfpy.LE_CONNECT:
        btfpy.Le_pair(
            clientnode,
            btfpy.AUTHENTICATION_ON | btfpy.PASSKEY_FIXED,
            123456
        )

    if operation == btfpy.LE_TIMER:
        # --- Get signal strength from morse_cli ---
        result = subprocess.run(
            "morse_cli -i wlan1 stats | grep Received | grep -o -E '\\-[0-9]+'",
            shell=True,
            capture_output=True,
            text=True
        )

        # Parse output
        value_str = result.stdout.strip()  # e.g. "-63", or "" if grep failed
        if not value_str:
            # Nothing parsed; skip this tick
            return btfpy.SERVER_CONTINUE
        try:
            # Convert to hex (Python int)
            rssi_hex = btfpy.Strtohex(value_str)
        except ValueError:
            # skip if unexpected output
            return btfpy.SERVER_CONTINUE

        # Write to characteristic (server-side update)
        btfpy.Write_ctic(
            btfpy.Localnode(),
            9,
            rssi_hex,
            0
        )

    return btfpy.SERVER_CONTINUE

btfpy.Init_blue("devices.txt")
btfpy.Le_server(le_callback,10)
