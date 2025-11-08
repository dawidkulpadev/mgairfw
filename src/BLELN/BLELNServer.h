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

struct RxPacket {
    uint32_t _a;
    uint16_t conH; // Connection handle
    size_t   len;
    uint8_t* buf;
};

class BLELNServer{
public:
    // User methods
    static void init();
    static void deinit();

    static void start(const uint8_t *name, const std::string &uuid);
    void stop();

    void startOtherServerSearch(uint32_t durationMs, const std::string &therUUID, const std::function<void(bool)>& onResult);

    bool getConnContext(uint16_t h, BLELNConnCtx** c);

    void setChDataTx(const std::string &s);
    void notifyChDataTx();
    void maybe_rotate(Preferences *prefs);


    bool noClientsConnected();

    void appendToQueue(uint16_t h, const std::string &m);
    void rxWorker();
    bool sendEncrypted(BLELNConnCtx *cx, const std::string& msg);
    bool sendEncrypted(uint16_t h, const std::string& msg);
    bool sendEncrypted(const std::string& msg);

    void setOnMessageReceivedCallback(std::function<void(uint16_t cliH, const std::string& msg)> cb);

    static void connected_cb(struct bt_conn *conn, uint8_t err);
    static void disconnected_cb(struct bt_conn *conn, uint8_t reason);

private:
    // RX kolejka i wątek
    struct k_fifo rx_fifo{};
    struct k_thread rx_thread{};
    bool runRxWorker = false;
    bool rxWorkerPaused = true;

    int start_advertising(const char *name);

    std::function<void(uint16_t cliH, const std::string& msg)> onMsgReceived;

    std::string serviceUUID;

    // Multithreading
    struct k_mutex clisMtx;
    struct k_mutex keyExTxMtx;
    struct k_mutex txMtx;

    // Encryption
    uint8_t g_psk_salt[32];
    uint32_t g_epoch = 0;
    uint32_t g_lastRotateMs = 0;

    // BLELN
    std::vector<BLELNConnCtx> connCtxs;
    bool runRxWorker=false;

    bool scanning = false;
    std::function<void(bool found)> onScanResult;
    std::string searchedUUID;

    // Private methods
    bool sendEncrypted(int i, const std::string& msg);
    void sendKeyToClient(BLELNConnCtx *cx);

    // Callbacks


    void onKeyExTxSubscribe(NimBLECharacteristic *pCharacteristic, NimBLEConnInfo &connInfo, uint16_t subValue);

    // Callbacks
    static void onDataWrite(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                            const void *buf, uint16_t len, uint16_t offset, uint8_t flags);
    static void onKeyExRxWrite(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                               void *buf, uint16_t len, uint16_t offset);

    void onResult(const NimBLEAdvertisedDevice* advertisedDevice) override;
    void onScanEnd(const NimBLEScanResults& scanResults, int reason) override;
    void onConnect(NimBLEServer* pServer, NimBLEConnInfo& connInfo) override;
    void onDisconnect(NimBLEServer* pServer, NimBLEConnInfo& connInfo, int reason) override;

};


#endif //MGLIGHTFW_G2_BLELNSERVER_H
