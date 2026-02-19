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

#ifndef MGLIGHTFW_G2_BLELNCLIENT_H
#define MGLIGHTFW_G2_BLELNCLIENT_H

#include "BLELNBase.h"
#include "BLELNConnCtx.h"
#include "BLELNAuthentication.h"

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/bluetooth/hci.h>
#include <functional>
#include <string>

class BLELNClient {
public:
    // User methods
    static void init(const uint8_t *certSign, const uint8_t *manuPubKey, const uint8_t *myPrivateKey,
                     const uint8_t *myPublicKey, const std::string &userId);
    static void deinit();

    static void start(const std::string& name, std::function<void(const std::string&)> onServerResponse);
    static void stop();
    static bool startServerSearch(uint32_t durationMs,
                           const std::string& serverUUID,
                           const std::function<bool(const bt_addr_le_t* addr)>& onResult);
    static bool beginConnect(const bt_addr_le_t* addr, const std::function<void(bool, int, uint8_t*)>& onConnectResult);
    static bool sendEncrypted(const std::string& msg);
    static void disconnect(int reason);

    static bool isScanning();
    static bool isConnecting();
    static bool isConnected();

    static void setOnDisconnectCallback(const std::function<void(int reason, uint8_t*)>& onDisconnect);

    void worker();
    void appendActionToQueue(uint8_t type, uint16_t conH, const uint8_t *data, size_t dataLen);

    static void connected_cb(struct bt_conn *conn, uint8_t err);
    static void disconnected_cb(struct bt_conn *conn, uint8_t reason);

    static std::string addrToRawHex(const bt_addr_le_t *addr);

private:

    BLELNClient(const uint8_t* certSign, const uint8_t* manuPubKey, const uint8_t* myPrivateKey, const uint8_t* myPublicKey, const std::string &userId);
    bool discover();
    bool handshake(uint8_t *v, size_t vlen);
    static void device_found_cb_new(const bt_addr_le_t *addr, int8_t rssi, uint8_t adv_type, struct net_buf_simple *buf);
    void handle_adv(const bt_addr_le_t *addr, struct net_buf_simple *ad);

    static uint8_t discover_func(struct bt_conn *conn,
                                 const struct bt_gatt_attr *attr,
                                 struct bt_gatt_discover_params *params);

    static void exchange_cb(struct bt_conn *conn, uint8_t err, struct bt_gatt_exchange_params *params);

    static uint8_t notify_keyex_cb(struct bt_conn *conn,
                                   struct bt_gatt_subscribe_params *params,
                                   const void *data, uint16_t length);
    static uint8_t notify_data_cb(struct bt_conn *conn,
                                  struct bt_gatt_subscribe_params *params,
                                  const void *data, uint16_t length);

    struct k_work_delayable scanTimeoutWork{};
    static void scan_timeout_handler(struct k_work *item);

    void onKeyExNotify(const uint8_t* pData, size_t length);
    void onDataNotify(const uint8_t* pData, size_t length);

    void worker_beginConnection(const bt_addr_le_t* addr);
    void worker_registerConnection(uint16_t h, uint8_t *mac);
    void worker_deleteConnection();
    void worker_sendMessage(uint8_t *data, size_t dataLen);
    void worker_processKeyRx(uint8_t *data, size_t dataLen);
    void worker_processDataRx(uint8_t *data, size_t dataLen);

    void sendCertToServer(BLELNConnCtx *cx);
    void sendChallengeNonceSign(BLELNConnCtx *cx, const std::string &nonceB64);

    void clearWorkerQueue();

    int64_t lastWaterMarkPrint{};
    k_mutex connCtxLock{};
    BLELNConnCtx *connCtx= nullptr;
    BLELNAuthentication authStore;

    // Konfiguracja/stan
    bool scanning = false;
    std::function<bool(const bt_addr_le_t* addr)> onScanResultCb; // return true if want to want to stop scan
    std::function<void(const std::string& msg)> onMsgRx;
    std::function<void(bool success, int err, uint8_t* macBE)> onConRes;
    std::function<void(int reason, uint8_t* mac)> onDisconnectCb{};

    // BT
    struct bt_conn* conn = nullptr;

    // Discovery handles
    uint16_t h_keyex_tx = 0; // value handle ch. (notify)
    uint16_t h_keyex_rx = 0; // value handle ch. (write)
    uint16_t h_data_tx  = 0; // value handle ch. (notify)
    uint16_t h_data_rx  = 0; // value handle ch. (write)

    struct bt_gatt_discover_params disc_params{};
    struct bt_gatt_exchange_params ex_params{};
    struct bt_gatt_subscribe_params sub_keyex{};
    struct bt_gatt_subscribe_params sub_data{};
    struct bt_gatt_discover_params keyex_ccc_disc_params{};
    struct bt_gatt_discover_params data_ccc_disc_params{};

    // RX kolejka i wątek
    struct k_fifo workerActionQueue{};
    struct k_thread rx_thread{};
    bool runWorker = false;


    // Narzędzia
    static bool parse_uuid128(const std::string& s, bt_uuid_128* out);
};

#endif // MGLIGHTFW_G2_BLELNCLIENT_H