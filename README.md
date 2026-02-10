# MioGiapicco Air Firmware

## Building
Generating firmware image key for MCUBoot image verification
```
export LD_LIBRARY_PATH=/home/dkulpa/ToolBox/programs/nRFConnectSDK/ncs/toolchains/43683a87ea/usr/local/lib
MY_PYTHON="/home/dkulpa/ToolBox/programs/nRFConnectSDK/ncs/toolchains/43683a87ea/usr/local/bin/python3"
IMGTOOL_SCRIPT="/home/dkulpa/ToolBox/programs/nRFConnectSDK/ncs/v3.2.1/bootloader/mcuboot/scripts/imgtool.py"
$MY_PYTHON $IMGTOOL_SCRIPT keygen -k root-rsa-2048.pem -t rsa-2048
```

Building image (marged with mcuboot)
```
export PATH="/home/dkulpa/ToolBox/programs/nRFConnectSDK/ncs/toolchains/43683a87ea/usr/local/bin:$PATH"
export ZEPHYR_TOOLCHAIN_VARIANT=zephyr
export ZEPHYR_SDK_INSTALL_DIR="/home/dkulpa/ToolBox/programs/nRFConnectSDK/ncs/toolchains/43683a87ea/opt/zephyr-sdk"
cd /home/dkulpa/ToolBox/programs/nRFConnectSDK/ncs/v3.2.1/zephyr
source zephyr-env.sh
cd ~/ToolBox/projects/MioGiapicco/Software/firmwares/mgairfw
west build -p always -b nrf52840dk/nrf52840 -d build_test
```

## Programming

Set ethernet adapter settings
```text
IPv4
  - address: 192.168.7.254
  - mask: 24
  - gateway: 192.168.7.1
  
IPv6
  - turned off
```

Connect configured RaspberryPi Zero.

Run _flash.sh_ script. Image path is defined in file as FIRMWARE_PATH.