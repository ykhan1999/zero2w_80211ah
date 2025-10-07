
## Overview

A tested and working framework to add 802.11ah (WiFi HaLow) support to the Raspberry Pi Zero 2W using the Heltec HT-HC01P module (and possibly other SPI-based modules) in SPI mode.

## Features

### Currently active
* Scripts to quickly install kernel modules & drivers for AP and STA (client) support 
* Easy AP mode setup with static IP and NAT forwarding --> Allows users to connect to AP's HaLow network and forward traffic through the AP's 2.4 GHz link

### TBD

* (Easy STA mode setup with NAT forwarding --> Allow user to connect to STA's 2.4 GHz network and forward traffic through the HaLow link
* Custom, open-source HAT for easy interfacing between Zero 2W and HT-HC01P
* Web GUI and iOS/Android app with...
	* Easy configuration wizard & reset options
	* Advanced options (channel, bandwidth, tx power, etc.)
	* Stats monitoring
	* Web terminal for direct CLI access
* Add support for SDIO and other MM6108-based chips
* Add watchdog to restart if unexpected errors occur

## Quick start guide

### Step 0: Prerequisites

1. Raspberry Pi Zero 2W device
2. Heltec HT-HC01P or other SPI-based MM6108 board

### Step 1: Wiring
Connect the SPI pins to the Raspberry Pi headers per the table below:
* Notes: If using the HT-HC01P, prototyping the wiring is a lot easier if you use the official debug board. If you decide to use different RPi GPIO pins, you will have to update the device tree overlay accordingly.
```
#SPI interface (GPIO 7-11, only 8-11 used)
#+----------------+--------------------+----------------------------+------------------------------+
#| HC01P Pin      | SPI Role           | RPi Signal / GPIO          | Notes                        |
#+----------------+--------------------+----------------------------+------------------------------+
#| 3V3            | Power              | 3V3 (Pin 1 or 17)          | Module VDD 3.3 V             |
#| GND            | Ground             | Any GND (6/9/14/20/25/30…) | Common ground                |
#| INT            | Host IRQ           | GPIO 25  (Pin 22)          | Module -> host interrupt     |
#| RESET          | Reset              | GPIO 5   (Pin 29)          | Active LOW                   |
#| BUSY           |  Wake sequence     | GPIO 7   (Pin 26)          | In POWER device tree overlay |
#| WAKE           | WL_REG_ON / EN     | GPIO 3   (Pin 5)           | Active HIGH                  |
#| CLK            | SPI0 SCLK          | GPIO 11  (Pin 23)          | SPI clock                    |
#| MISO           | SPI0 MISO          | GPIO 9   (Pin 21)          | 1-bit data line              |
#| MOSI           | SPI0 MOSI          | GPIO 10  (Pin 19)          | SPI command line             |
#| CS             | SPI0 CEO0          | GPIO 8   (Pin 24)          |                              |
#+----------------+--------------------+----------------------------+------------------------------+
```
### Step 2: Installing the kernel & drivers
1. Using your preferred imaging tool (ex., Raspberry Pi Imager), flash the Pi Zero 2W with the official 2025-10-01 Raspberry Pi OS Lite release: https://downloads.raspberrypi.com/raspios_lite_arm64/images/raspios_lite_arm64-2025-10-02/2025-10-01-raspios-trixie-arm64-lite.img.xz
2. Connect to the Raspberry Pi, either via SSH or physically with a display and keyboard
3. Clone the repo and run the kernel install script
```bash
sudo apt-get update
sudo apt install git
git clone https://github.com/ykhan1999/zero2w_80211ah
./zero2w_80211ah/scripts/install_kernel.sh
#Should auto reboot, but if it doesn't:
sudo reboot
```
4. Install the drivers
```bash
./zero2w_80211ah/scripts/install_drivers.sh
```
5. Install the device tree overlay and patches for the SPI interface
```bash
./zero2w_80211ah/scripts/install_SPI_overlays.sh
#If no auto reboot:
sudo reboot
```
Done! Your module should be brought up now, and you should see the interface "wlan1" when you run ifconfig. 

### AP Mode setup

0. (One-time setup) Edit the sample config (zero2w_80211ah/sample_configs/hostapd.conf) with your desired parameters, and then run the initialization script:
```bash
./zero2w_80211ah/scripts/init_AP.sh
```

* Turn on AP with NAT forwarding to wlan0 (the 2.4GHz network)
```bash
./zero2w_80211ah/scripts/start_AP.sh
```

After running the command, you should be able to connect a HaLow STA to your AP and access resources on the 2.4GHz network (including the internet).

* Turn off AP and NAT forwarding
```bash
./zero2w_80211ah/scripts/stop_AP.sh
```

### STA mode setup

TBD, check back for updates

## Building from source (advanced)

See source_compile_instructions.txt; instructions are provided for compiling the kernel and modules and installing into a staging directory. To install on your device, see zero2w_80211ah/packages as a reference for where to install everything.

## Acknowledgements

This project builds upon the work of many talented engineers and open-source contributors.  
Special thanks and credit are due to:

-   **Morse Micro, Inc.** — for developing the **MM6108 Wi-Fi HaLow (802.11ah)** chipset and the associated Linux driver stack.  
    Portions of this repository integrate or modify code from Morse Micro’s [morse_driver](https://github.com/MorseMicro/morse_driver?utm_source=chatgpt.com) and related open-source releases.
    
-   **The Linux kernel maintainers and contributors** — for maintaining the upstream kernel, networking subsystems, and SPI infrastructure that make this project possible.
    
-   **The Raspberry Pi Foundation** — for maintaining the Raspberry Pi OS distribution, firmware, and device-tree infrastructure.
    
-   **Open-source contributors worldwide** — whose work across the Linux ecosystem (toolchains, packaging utilities, and supporting libraries) underpins this project.
    
Any referenced trademarks, products, or company names are property of their respective owners.

## License

This project is licensed under the **GNU General Public License v2 only (GPL-2.0)**, to ensure compatibility with the Morse Micro driver and the Linux kernel.

You may copy, distribute, and/or modify this software under the terms of the **GNU General Public License version 2**, as published by the **Free Software Foundation**.

A copy of the full license text is provided in the `LICENSE` file.  
Unless otherwise noted, all derivative or redistributed components must remain under GPL-2.0-compatible terms.
