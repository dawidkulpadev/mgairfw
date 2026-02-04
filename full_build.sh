#!/bin/bash

export PATH="/home/dkulpa/ToolBox/programs/nRFConnectSDK/ncs/toolchains/43683a87ea/usr/local/bin:$PATH"
export ZEPHYR_TOOLCHAIN_VARIANT=zephyr
export ZEPHYR_SDK_INSTALL_DIR="/home/dkulpa/ToolBox/programs/nRFConnectSDK/ncs/toolchains/43683a87ea/opt/zephyr-sdk"
cd /home/dkulpa/ToolBox/programs/nRFConnectSDK/ncs/v3.2.1/zephyr
source zephyr-env.sh
cd ~/ToolBox/projects/MioGiapicco/Software/firmwares/mgairfw
west build -p always -b nrf52840dk/nrf52840 -d build_test
