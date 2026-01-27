
## Overview

A tested and working framework to add 802.11ah (WiFi HaLow) support to the Raspberry Pi Zero 2W using the MM6108 module in SPI mode using the country=US firmware blob.

## Features

### Currently active
* Scripts to quickly install kernel modules & drivers for 802.11ah support 
* Support for SSD1306 display
* Web GUI for easy configuration
* mesh mode (802.11s)
	* Gateway mode - essentially acts as an AP, with forwarding from the connected 2.4GHz through the HaLow network
    * Client mode - Acts as a hotspot, allowing access to resources forwarded from the gateway through the HaLow network

## Quick start

Download the software image contained at the link below, download the [Raspberry Pi Imager](https://www.raspberrypi.com/software/) utility, and use the imager to flash the image to a micro SD card. 

http://y3782016.eero.online/4dedf43.img.xz

Insert the micro SD card into your raspberry pi, and if all is successful, you should see a welcome message on the SSD1306 display. If you don't have a display, you can connect via USB and go to http://10.42.0.1 to begin the configuration wizard.

## Full setup without using quick start image

### Step 0: Prerequisites

1. Raspberry Pi Zero 2W
2. MM6108 module in SPI mode - I used the Heltec HT-HC01P board
3. (Optional) SSD1306-driven 128x64 OLED display - I used a cheap Amazon module

### Step 1: Wiring the MM6108
Keep in mind that this wiring is for SPI, not GPIO interfacing!
```
#+----------------+--------------------+----------------------------+------------------------------+
#| MM6108         | Role               | RPi Signal / GPIO          | Notes                        |
#+----------------+--------------------+----------------------------+------------------------------+
#| 3V3            | Power              | 3.3 (Pin 1 or 17)          | Module VDD 3.3 V             |
#| GND            | Ground             | Any GND (6/9/14/20/25/30…) | Common ground                |
#| INT            | Host IRQ           | GPIO 25  (Pin 22)          | Module -> host interrupt     |
#| RESET          | Reset              | GPIO 5   (Pin 29)          | Active LOW  --> resets module|
#| BUSY           |  Wake sequence     | GPIO 7   (Pin 26)          | \*See below                   |
#| WAKE           | WL_REG_ON / EN     | GPIO 3   (Pin 5)           | Active HIGH --> wakes module |
#| CLK            | SPI0 SCLK          | GPIO 11  (Pin 23)          | SPI clock                    |
#| MISO           | SPI0 MISO          | GPIO 9   (Pin 21)          | SPI data line                |
#| MOSI           | SPI0 MOSI          | GPIO 10  (Pin 19)          | SPI command line             |
#| CS             | SPI0 CEO0          | GPIO 8   (Pin 24)          |                              |
#+----------------+--------------------+----------------------------+------------------------------+
\*I'm not actually sure what this does but it's included in the wake sequence of the device tree overlay per the documentation so I left it
```

### Step 1.5 (Optional): Wiring the SSD1306 128x64 display
Because we are using the main I2C interface pins for our MM6108 module, we have to use the alternate I2C pins as below:
```
#+----------------+--------------------+----------------------------+------------------------------+
#| SSD1306        | Role               | RPi Signal / GPIO          | Notes                        |
#+----------------+--------------------+----------------------------+------------------------------+
#| VCC            | 3.3V or 5V Power   | 3V3 (Pin 1 or 17)          | Module VDD 3.3 V             |
#| GND            | Ground             | Any GND (6/9/14/20/25/30…) | Common ground                |
#| SCL            | I2C clock          | GPIO 1  (Pin 28)           | clock line                   |
#| SDA            | I2C data           | GPIO 0  (Pin 27)           | data line                    |
#+----------------+--------------------+----------------------------+------------------------------+
\*I'm not actually sure what this does but it's included in the wake sequence of the device tree overlay per the documentation so I left it
```

### Step 2: Installing the kernel & drivers

1. Using your preferred imaging tool (ex., Raspberry Pi Imager), flash the Pi Zero 2W with the official 2025-10-01 Raspberry Pi OS Lite release: [Official mirror](https://downloads.raspberrypi.com/raspios_lite_arm64/images/raspios_lite_arm64-2025-10-02/2025-10-01-raspios-trixie-arm64-lite.img.xz) | [Self-hosted backup](http://y3782016.eero.online/2025-10-01-raspios-trixie-arm64-lite.img.xz)

Note: You will want to set up SSH and WiFi if you plan to configure headlessly. This is fine, the scripts will remove the preconfigured WiFi info once setup completes. 

2. Connect to the Raspberry Pi, either via SSH or physically with a display and keyboard

3. Clone the repo
```bash
sudo apt-get update
sudo apt install -y git=1:2.47.3-0+deb13u1
git clone https://github.com/ykhan1999/zero2w_80211ah
```

4. Run the install scripts in the following order
```bash
./zero2w_80211ah/scripts/init/install_kernel.sh
#Wait for system reboot before proceeding
./zero2w_80211ah/scripts/init/install_drivers_1.sh
./zero2w_80211ah/scripts/init/install_drivers_2.sh
./zero2w_80211ah/scripts/init/install_SPI_overlays.sh
#Wait for reboot
./zero2w_80211ah/scripts/init/install_mesh_helpers.sh
./zero2w_80211ah/scripts/init/install_display_drivers.sh
#Wait for reboot
./zero2w_80211ah/scripts/init/install_USB_ether_serv.sh
#Wait for reboot
./zero2w_80211ah/scripts/init/install_webserver.sh
#On reboot, the webserver should be up, proceed to step 3
```

### Step 3: Configuration

1. Once all the install scripts are run, after 2-3 minutes, you should see a WiFi network "ExtendFi". Connect to the network. Note that there is a randomly generated password associated that is displayed on the OLED screen, so if you have not configured the display, you will need to connect via USB. The device will automatically act as a USB ethernet server - just make sure you use the usb data port and not the power only port.

2. Go to http://10.42.0.1

3. Follow the prompts to configure as either a gateway or a client.

For gateway mode, for the Wifi SSID and password, you will input your home network WiFi SSID and password. For client mode, you will input the SSID and password of the hotspot you want to create. The HaLow SSID and password can be anything but they must match between the client and gateway.

4. Your device will reboot, and you should be all set! Note that for a functional system you will need both a gateway and receiver.


## Building from source (advanced)

See source_compile_instructions.txt; instructions are provided for compiling the kernel and modules and installing into a staging directory. To install on your device, see zero2w_80211ah/packages as a reference for where to install everything.

## Technical limitations

* This software currently only official supports the Raspberry Pi Zero 2W and the Heltec HT-HC01P HaLow module. Those interested in seeing additional support are encouraged to contribute to the repo.

* No support yet for open WiFi networks or captive WiFi networks

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
