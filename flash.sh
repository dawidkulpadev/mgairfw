#!/bin/bash

FIRMWARE_PATH=/home/dkulpa/ToolBox/projects/MioGiapicco/Software/firmwares/mgairfw/build/merged.hex
scp -o IdentitiesOnly=yes -i ~/.ssh/rpi_swd_id_rsa $FIRMWARE_PATH dkulpa@192.168.7.2:/tmp/fw.hex
ssh dkulpa@192.168.7.2 "sudo openocd -f /home/dkulpa/rpi-swd.cfg -f target/nordic/nrf52.cfg -c ' init; nrf52_recover; reset halt; program /tmp/fw.hex verify reset exit'"