#!/usr/bin/env bash
modprobe morse enable_wiphy=0 enable_otp_check=1 country=US bcf=bcf_boardtype_0801.bin spi_clock_speed=24000000 slow_clock_mode=0 fw_bin_file=mm6108.bin debug_mask=2
