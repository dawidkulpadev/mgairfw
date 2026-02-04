#ifndef MGLIGHTFW_G2_BLELNCLIENT_H
#define MGLIGHTFW_G2_BLELNCLIENT_H

#include "BLELNBase.h"

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

struct RxClientPacket {
    uint32_t _a;
    size_t   len;
    uint8_t* buf;
};

class BLELNClient {
public:
    void start(const std::string& name, std::function<void(const std::string&)> onServerResponse);
    void stop();
    void startServerSearch(uint32_t durationMs,
                           const std::string& serverUUID,
                           const std::function<void(const bt_addr_le_t* addr)>& onResult);
    void beginConnect(const bt_addr_le_t* addr, const std::function<void(bool, int)>& onConnectResult);
    bool discover();
    bool handshake();
    bool sendEncrypted(const std::string& msg);
    void disconnect();

    bool isScanning() const { return scanning; }
    bool isConnected() const { return conn != nullptr; }
    bool hasDiscoveredClient() const { return have_handles; }

static void auth_passkey_entry(struct bt_conn *conn);
    static void auth_cancel(struct bt_conn *conn);
    static void connected_cb(struct bt_conn *conn, uint8_t err);
    static void disconnected_cb(struct bt_conn *conn, uint8_t reason);

private:
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

    void onKeyExNotify(const uint8_t* pData, size_t length);
    void onServerResponseNotify(const uint8_t* pData, size_t length);

    // --- RX worker
    void rxWorker();
    void appendToQueue(const uint8_t* pData, size_t length);

    bool parseAdData(struct bt_data *data, void *user_data);

private:
    // Konfiguracja/stan
    bool scanning = false;
    std::function<void(const bt_addr_le_t* addr)> onScanResult;
    std::function<void(const std::string&)> onMsgRx;
    std::function<void(bool,int)> onConRes;

    // BT
    struct bt_conn* conn = nullptr;

    // Discovery handles
    bool have_handles = false;
    uint16_t h_keyex_tx = 0; // value handle ch. (notify)
    uint16_t h_keyex_rx = 0; // value handle ch. (write)
    uint16_t h_data_tx  = 0; // value handle ch. (notify)
    uint16_t h_data_rx  = 0; // value handle ch. (write)

    struct bt_gatt_discover_params disc_params{};
    struct bt_gatt_subscribe_params sub_keyex{};
    struct bt_gatt_subscribe_params sub_data{};
    struct bt_gatt_discover_params keyex_ccc_disc_params{};
    struct bt_gatt_discover_params data_ccc_disc_params{};

    // RX kolejka i wątek
    struct k_fifo rx_fifo{};
    struct k_thread rx_thread{};
    bool runRxWorker = false;
    bool rxWorkerPaused = true;


    // Handshake state
    volatile bool g_keyexReady = false;
    std::string   g_keyexPayload;

    volatile uint16_t s_sid = 0;
    uint32_t s_epoch = 0;
    uint8_t  s_salt[32]{};
    uint8_t  s_srvPub[65]{}, s_srvNonce[12]{};
    uint8_t  s_cliPub[65]{}, s_cliNonce[12]{};
    uint8_t  s_sessKey_c2s[32]{}, s_sessKey_s2c[32]{};
    uint32_t s_ctr_c2s = 0, s_ctr_s2c = 0;

    // Narzędzia
    static bool parse_uuid128(const std::string& s, bt_uuid_128* out);
    static BLELNClient* self_from_conn(struct bt_conn* c);
};

#endif // MGLIGHTFW_G2_BLELNCLIENT_H