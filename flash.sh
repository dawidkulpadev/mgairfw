#!/bin/bash

MCUBOOT_PATH=/home/dkulpa/ToolBox/projects/MioGiapicco/Software/firmwares/mgairfw-zephyr-workspace/bootloader/mcuboot/boot/zephyr/build/zephyr/zephyr.hex
FIRMWARE_PATH=/home/dkulpa/ToolBox/projects/MioGiapicco/Software/firmwares/mgairfw-zephyr-workspace/mgairfw/build/zephyr/zephyr.signed.hex
scp -o IdentitiesOnly=yes -i ~/.ssh/rpi_swd_id_rsa $FIRMWARE_PATH dkulpa@192.168.7.2:/tmp/firmware.hex
scp -o IdentitiesOnly=yes -i ~/.ssh/rpi_swd_id_rsa $MCUBOOT_PATH dkulpa@192.168.7.2:/tmp/mcuboot.hex
ssh dkulpa@192.168.7.2 "sudo openocd -f /home/dkulpa/rpi-swd.cfg -f target/nordic/nrf52.cfg -c ' init; nrf52_recover; reset halt; program /tmp/mcuboot.hex verify; program /tmp/firmware.hex verify reset exit'"