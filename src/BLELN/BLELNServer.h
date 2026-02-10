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

#ifndef MGLIGHTFW_G2_BLELNSERVER_H
#define MGLIGHTFW_G2_BLELNSERVER_H

#include <list>

#include "zephyr/kernel.h"
#include "BLELNConnCtx.h"
#include "BLELNBase.h"
#include "BLELNAuthentication.h"

#include <zephyr/sys/printk.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/bluetooth/hci.h>

#include <mbedtls/gcm.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h> // HMAC (HKDF implementujemy ręcznie)
#include <functional>
#include <memory>

#include "BLELNCert.h"

class BLELNServer{
public:
    // User methods
    static void init();     // <- Run this first!!!
    static void deinit();

    static void start(const char *name, const std::string &uuid, BLELNCert *myCert);
    static void stop();

    static bool sendEncrypted(uint16_t h, const std::string& msg);
    static bool sendEncryptedToAll(const std::string& msg);

    static void setOnMessageReceivedCallback(std::function<void(uint16_t cliH, const std::string& msg)> cb);

    // Internal methods
    static bool getConnContext(uint16_t h, BLELNConnCtx** c);
    bool noClientsConnected();
    void worker();


// Callbacks
    static void connected_cb(struct bt_conn *conn, uint8_t err);
    static void disconnected_cb(struct bt_conn *conn, uint8_t reason);
    static ssize_t onDataWrite(struct bt_conn *conn, [[maybe_unused]] const struct bt_gatt_attr *attr,
                               const void *buf, uint16_t len, uint16_t offset, [[maybe_unused]] uint8_t flags);
    static ssize_t onKeyExRxWrite(struct bt_conn *conn, [[maybe_unused]] const struct bt_gatt_attr *attr,
                                  const void *buf, uint16_t len, uint16_t offset, uint8_t flags);
    static void onKeyExTxSubscribe(const struct bt_gatt_attr *attr, uint16_t value);

private:
    BLELNServer(){}

    std::string advName;

    // RX kolejka i wątek
    struct k_fifo rx_fifo{};
    struct k_thread rx_thread{};
    bool runWorker = false;

    static int startAdvertising(const char *name);

    static bool callbacksRegistered;

    std::function<void(uint16_t cliH, const std::string& msg)> onMsgReceived;

    std::string serviceUUID;

    // Private methods
    void worker_registerClient(uint16_t h);
    void worker_deleteClient(uint16_t h);
    void worker_processSubscription();
    void worker_sendMessage(uint16_t h, uint8_t *data, size_t dataLen);
    void worker_processKeyRx(uint16_t h, uint8_t *data, size_t dataLen);
    void worker_processDataRx(uint16_t h, uint8_t *data, size_t dataLen);
    void worker_cleanup();

    bool _sendEncrypted(BLELNConnCtx *cx, const std::string& msg);
    void sendKeyToClient(BLELNConnCtx *cx);
    void sendCertToClient(BLELNConnCtx *cx);
    void sendChallengeNonce(BLELNConnCtx *cx);
    void sendChallengeNonceSign(BLELNConnCtx *cx, uint8_t *sign);
    void disconnectClient(BLELNConnCtx *cx, uint8_t reason);
    void appendToDataQueue(uint16_t h, const void *buf, uint16_t len);
    void appendToKeyQueue(uint16_t h, const void *buf, uint16_t len);

    // Multithreading
    struct k_mutex clisMtx{};

    uint64_t lastWaterMarkPrint= 0;

    // Encryption
    uint8_t g_psk_salt[32]{};
    uint32_t g_epoch = 0;
    uint32_t g_lastRotateMs = 0;

    // BLELN
    BLELNAuthentication authStore;
    std::list<BLELNConnCtx> connCtxs;

    bool scanning = false;
    std::function<void(bool found)> onScanResult;
    std::string searchedUUID;
};


#endif //MGLIGHTFW_G2_BLELNSERVER_H
