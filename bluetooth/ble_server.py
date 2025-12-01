#!/usr/bin/python3

import btfpy

def le_callback(clientnode,operation,cticn):
    if(operation == btfpy.LE_CONNECT):
        btfpy.Le_pair(clientnode,btfpy.AUTHENTICATION_ON | btfpy.PASSKEY_FIXED,123456)

btfpy.Init_blue("devices.txt")
btfpy.Le_server(le_callback,0)
