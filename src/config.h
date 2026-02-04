//
// Created by dkulpa on 11.08.24.
//

#ifndef MGLIGHTFW_CONF_H
#define MGLIGHTFW_CONF_H

#define DEVICE_MODE_CONFIG             1
#define DEVICE_MODE_NORMAL             2



/**
 * Firmware version number - 32 bit number
 * (16-bit)hw_id, (16-bit, 15-0 bits)sw_version
 * Hardware id: (6-bit) hw type, (10-bit) hw type version
 *      Hardware type:
 *          * 1 - Light
 *          * 2 - Air?
 *          # 3 - Soil?
 * Software version: (5-bit) sw epoch, (7-bit) sw epoch version, (4-bit) sw epoch version fix
 */

#define BLE_NAME    "MioGiapicco Air Gen2"
#define BLELN_CONFIG_UUID           "e0611e96-d399-4101-8507-1f23ee392891"
#define BLELN_HTTP_REQUESTER_UUID   "952cb13b-57fa-4885-a445-57d1f17328fd"

constexpr uint32_t sw_epoch= 1;
constexpr uint32_t sw_epoch_version= 1;
constexpr uint32_t sw_epoch_version_fix= 1;
constexpr uint32_t sw_version= (sw_epoch << 11) | (sw_epoch_version << 4) | sw_epoch_version_fix;

#define HW_0_0

#ifdef HW_0_0
constexpr uint32_t hw_type= 2;
constexpr uint32_t hw_version= 1;
constexpr uint32_t hw_id= (hw_type<<10) | hw_version;

constexpr uint32_t fw_version= (hw_id << 16) | sw_version;
#endif


#endif //MGLIGHTFW_CONF_H