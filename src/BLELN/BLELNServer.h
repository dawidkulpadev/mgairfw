//
// Created by dkulpa on 17.08.2025.
//

#ifndef MGLIGHTFW_G2_BLELNSERVER_H
#define MGLIGHTFW_G2_BLELNSERVER_H

#include <vector>

#include "zephyr/kernel.h"
#include "BLELNConnCtx.h"
#include "BLELNBase.h"

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


struct RxPacket {
    uint32_t _a;
    uint16_t conH; // Connection handle
    size_t   len;
    uint8_t* buf;
};

class BLELNServer{
public:
    // User methods
    static void init();     // <- Run this first!!!
    static void deinit();

    static void start(const char *name, const std::string &uuid);
    static void stop();

    // Internal methods
    static bool getConnContext(uint16_t h, BLELNConnCtx** c);

    bool noClientsConnected();

    void appendToQueue(uint16_t h, const std::string &m);
    void rxWorker();
    static bool sendEncrypted(BLELNConnCtx *cx, const std::string& msg);
    static bool sendEncrypted(uint16_t h, const std::string& msg);
    static bool sendEncrypted(const std::string& msg);

    static void setOnMessageReceivedCallback(std::function<void(uint16_t cliH, const std::string& msg)> cb);

    static void connected_cb(struct bt_conn *conn, uint8_t err);
    static void disconnected_cb(struct bt_conn *conn, uint8_t reason);

    // Callbacks
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
    bool runRxWorker = false;
    bool rxWorkerPaused = true;

    static int startAdvertising(const char *name);

    std::function<void(uint16_t cliH, const std::string& msg)> onMsgReceived;

    std::string serviceUUID;

    // Multithreading
    struct k_mutex clisMtx{};
    struct k_mutex keyExTxMtx{};
    struct k_mutex txMtx{};

    // Encryption
    uint8_t g_psk_salt[32]{};
    uint32_t g_epoch = 0;
    uint32_t g_lastRotateMs = 0;

    // BLELN
    std::vector<std::unique_ptr<BLELNConnCtx>> connCtxs;

    bool scanning = false;
    std::function<void(bool found)> onScanResult;
    std::string searchedUUID;

    // Private methods
    bool sendEncrypted(int i, const std::string& msg);
    void sendKeyToClient(BLELNConnCtx *cx);

    // Callbacks
};


#endif //MGLIGHTFW_G2_BLELNSERVER_H
