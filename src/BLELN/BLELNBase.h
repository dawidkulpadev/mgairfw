/**
    MioGiapicco Light Firmware - Firmware for Light Device of MioGiapicco system
    Copyright (C) 2026  Dawid Kulpa

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    Please feel free to contact me at any time by email <dawidkulpadev@gmail.com>
*/

#ifndef MGLIGHTFW_G2_BLELNBASE_H
#define MGLIGHTFW_G2_BLELNBASE_H

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/random/random.h>
#include <zephyr/settings/settings.h>
#include <zephyr/bluetooth/uuid.h>

#include <mbedtls/gcm.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <psa/crypto.h>

#include <cstdint>
#include <cstddef>
#include <string>
#include <cstring>

#define BLELN_TEST_NONCE_LEN        48
#define BLELN_DEV_PUB_KEY_LEN       64
#define BLELN_DEV_PRIV_KEY_LEN      32
#define BLELN_MANU_PUB_KEY_LEN      64
#define BLELN_DEV_SIGN_LEN          64
#define BLELN_MANU_SIGN_LEN         64
#define BLELN_NONCE_SIGN_LEN        64

#define BLELN_MSG_TITLE_CERT                                "$CERT"
#define BLELN_MSG_TITLE_CHALLENGE_RESPONSE_NONCE            "$CHRN"
#define BLELN_MSG_TITLE_CHALLENGE_RESPONSE_ANSW_AND_NONCE   "$CHRAN"
#define BLELN_MSG_TITLE_CHALLENGE_RESPONSE_ANSW             "$CHRA"
#define BLELN_MSG_TITLE_AUTH_OK                             "$AUOK"

void hexDump(const char* label, const uint8_t* data, size_t len);

enum blen_wroker_actions {
    BLELN_WORKER_ACTION_REGISTER_CONNECTION,
    BLELN_WORKER_ACTION_DELETE_CONNECTION,
    BLELN_WORKER_ACTION_PROCESS_SUBSCRIPTION,
    BLELN_WORKER_ACTION_PROCESS_DATA_RX,
    BLELN_WORKER_ACTION_PROCESS_KEY_RX,
    BLELN_WORKER_ACTION_SEND_MESSAGE,
    BLELN_WORKER_ACTION_SERVICE_DISCOVERED
};

typedef struct  {
    void *fifo_reserved;
    uint16_t connH;
    uint16_t type;
    size_t dlen;
    uint8_t *d;
} __attribute__((__packed__)) BLELNWorkerAction;


class BLELNBase {
public:
    static constexpr struct bt_uuid_128 CLIENT_SERVICE_UUID  =
            BT_UUID_INIT_128(BT_UUID_128_ENCODE(0x952cb13b, 0x57fa, 0x4885, 0xa445, 0x57d1f17328fd));
    static constexpr struct bt_uuid_128 CONFIGER_SERVICE_UUID =
            BT_UUID_INIT_128(BT_UUID_128_ENCODE(0xe0611e96, 0xd399, 0x4101, 0x8507 ,0x1f23ee392891));
    static constexpr struct bt_uuid_128 KEYEX_TX_UUID =
            BT_UUID_INIT_128(BT_UUID_128_ENCODE(0xef7cb0fc, 0x53a4, 0x4062, 0xbb0e, 0x25443e3a1f5d));
    static constexpr struct bt_uuid_128 KEYEX_RX_UUID =
            BT_UUID_INIT_128(BT_UUID_128_ENCODE(0x345ac506, 0xc96e, 0x45c6, 0xa418, 0x56a2ef2d6072));
    static constexpr struct bt_uuid_128 DATA_TX_UUID  =
            BT_UUID_INIT_128(BT_UUID_128_ENCODE(0xb675ddff, 0x679e, 0x458d, 0x9960, 0x939d8bb03572));
    static constexpr struct bt_uuid_128 DATA_RX_UUID  =
            BT_UUID_INIT_128(BT_UUID_128_ENCODE(0x566f9eb0, 0xa95e, 0x4c18, 0xbc45, 0x79bd396389af));
};

#endif // MGLIGHTFW_G2_BLELNBASE_H