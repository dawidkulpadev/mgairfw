//
// Created by dkulpa on 17.08.2025.
//

#include "BLELNServer.h"

#include <utility>
#include "BLELNBase.h"

K_THREAD_STACK_DEFINE(g_server_rx_stack, 2560)

static BLELNServer* instance = nullptr;
static struct bt_conn *current_conn = nullptr;

void BLELNServer::init() {
    instance= new BLELNServer();
}

void BLELNServer::deinit(){
    delete instance;
}

static struct bt_conn_cb s_conn_cb = {
        .connected    = BLELNServer::connected_cb,
        .disconnected = BLELNServer::disconnected_cb,
};


static const struct bt_le_adv_param *param = BT_LE_ADV_PARAM(
        BT_LE_ADV_OPT_CONN,
        0x00A0, /* min interval 100 ms */
        0x00F0, /* max interval 150 ms */
        nullptr);

static struct bt_data ad[] = {
        BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
        BT_DATA_BYTES(BT_DATA_UUID128_ALL, /* 16B little-endian */
                      0xef,0xcd,0xab,0x90,0x78,0x56,0x34,0x12, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
};

BT_GATT_SERVICE_DEFINE(ln_svc,
                       BT_GATT_PRIMARY_SERVICE(&BLELNBase::CONFIGER_SERVICE_UUID),

                       BT_GATT_CHARACTERISTIC(&BLELNBase::KEYEX_TX_UUID.uuid,
                                              BT_GATT_CHRC_NOTIFY,
                                              BT_GATT_PERM_NONE,
                                              nullptr, nullptr, nullptr),
                       BT_GATT_CCC(BLELNServer::onKeyExTxSubscribe, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),

                       BT_GATT_CHARACTERISTIC(&BLELNBase::KEYEX_RX_UUID.uuid,
                                              BT_GATT_CHRC_WRITE,
                                              BT_GATT_PERM_WRITE,
                                              nullptr, BLELNServer::onKeyExRxWrite, nullptr),

                       BT_GATT_CHARACTERISTIC(&BLELNBase::DATA_TX_UUID.uuid,
                                              BT_GATT_CHRC_READ | BT_GATT_CHRC_NOTIFY,
                                              BT_GATT_PERM_READ,
                                              nullptr, nullptr, nullptr),
                       BT_GATT_CCC(nullptr, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),

                       BT_GATT_CHARACTERISTIC(&BLELNBase::DATA_RX_UUID.uuid,
                                              BT_GATT_CHRC_WRITE,
                                              BT_GATT_PERM_WRITE,
                                              nullptr, BLELNServer::onDataWrite, nullptr)
);

int BLELNServer::startAdvertising(const char *name)
{
    struct bt_data sd[] = {
            BT_DATA(BT_DATA_NAME_COMPLETE, name, (uint8_t)strlen(name)),
    };

    bt_set_name(name);

    return bt_le_adv_start(param, ad, ARRAY_SIZE(ad), sd, ARRAY_SIZE(sd));
}


void BLELNServer::start(const char *name, const std::string &uuid) {
    if(instance == nullptr)
        BLELNServer::init();

    instance->advName= std::string(name);
    instance->serviceUUID= uuid;

    // BT on
    int err = bt_enable(nullptr);
    if (err) {
        printk("bt_enable err=%d\r\n", err);
        return;
    }

    err = settings_load();   // WAŻNE!
    printk("settings_load -> %d\n\r", err);

    bt_conn_cb_register(&s_conn_cb);

    k_mutex_init(&instance->clisMtx);
    k_mutex_init(&instance->keyExTxMtx);
    k_mutex_init(&instance->txMtx);
    k_fifo_init(&instance->rx_fifo);

    instance->runRxWorker= true;
    k_thread_create(&instance->rx_thread, g_server_rx_stack, K_THREAD_STACK_SIZEOF(g_server_rx_stack),
                    [](void* p1, void*, void*) {
                        instance->rxWorker();
                    },
                    nullptr, nullptr, nullptr, K_PRIO_COOP(8), 0, K_NO_WAIT);


    startAdvertising(instance->advName.c_str());
}


bool BLELNServer::getConnContext(uint16_t h, BLELNConnCtx** ctx) {
    *ctx = nullptr;

    if(k_mutex_lock(&instance->clisMtx, K_MSEC(100))!=0)
        return false;

    for (auto &c : instance->connCtxs){
        if (c->getHandle() == h){
            *ctx = c.get();
            break;
        }
    }
    k_mutex_unlock(&instance->clisMtx);

    return true;
}

void BLELNServer::sendKeyToClient(BLELNConnCtx *cx) {
    // KEYEX_TX: [ver=1][epoch:4B][salt:32B][srvPub:65B][srvNonce:12B]
    std::string keyex;
    keyex.push_back(1);
    keyex.append((const char*)&g_epoch, 4); // LE
    keyex.append((const char*)g_psk_salt, 32);
    keyex.append(cx->getEncData()->getPublicKeyString());
    keyex.append(cx->getEncData()->getNonceString());

    if(k_mutex_lock(&keyExTxMtx, K_MSEC(100)) == 0) {
        struct bt_conn *conn= bt_hci_conn_lookup_handle(cx->getHandle());
        struct bt_gatt_attr attr{};
        attr.handle= cx->getHandle();

        bt_gatt_notify_uuid(conn,
                            (struct bt_uuid*)&BLELNBase::KEYEX_TX_UUID,
                                    ln_svc.attrs, keyex.data(), keyex.length());
        cx->setKeySent(true);
        k_mutex_unlock(&keyExTxMtx);
    } else {
        printk("Failed locking semaphore! (Key Exchange)\r\n");
    }
}

void BLELNServer::appendToQueue(uint16_t h, const std::string &m) {
    auto* heapBuf = (uint8_t*)k_malloc(m.size());
    if (!heapBuf) return;
    memcpy(heapBuf, m.data(), m.size());
    auto* pkt = (RxPacket*)k_malloc(sizeof(RxPacket));
    if (!pkt) { k_free(heapBuf); return; }
    pkt->conH= h;
    pkt->len = m.size();
    pkt->buf = heapBuf;
    k_fifo_put(&rx_fifo, pkt);
}

void BLELNServer::rxWorker() {
   for(;;) {
        if(!runRxWorker){
            auto *node = static_cast<RxPacket *>(k_fifo_get(&rx_fifo, K_TICKS(1)));
            while (node) {
                k_free(node->buf);
                k_free(node);
                node= static_cast<RxPacket *>(k_fifo_get(&rx_fifo, K_TICKS(1)));
            }

            return;
        }

       auto *node = static_cast<RxPacket *>(k_fifo_get(&rx_fifo, K_MSEC(10)));
        if (node) {
            BLELNConnCtx *cx;
            if(getConnContext(node->conH, &cx) and (cx!= nullptr)) {
                std::string v(reinterpret_cast<char*>(node->buf), node->len);

                std::string plain;
                if (cx->getEncData()->decryptAESGCM((const uint8_t *) v.data(), v.size(), plain)) {
                    if (plain.size() > 200) plain.resize(200);
                    for (auto &ch: plain) if (ch == '\0') ch = ' ';

                    if(onMsgReceived)
                        onMsgReceived(cx->getHandle(), plain);
                } else {
                    // TODO: Inform error
                }
            }

            k_free(node->buf);
            k_free(node);
        }

        if(k_fifo_is_empty(&rx_fifo)){
            k_sleep(K_MSEC(50));
        } else {
            k_sleep(K_MSEC(1));
        }
    }
}

bool BLELNServer::sendEncrypted(BLELNConnCtx *cx, const std::string &msg) {
    std::string encrypted;
    if(!cx->getEncData()->encryptAESGCM(msg, encrypted)){
        printk("Encrypt failed\r\n");
        return false;
    }

    bt_gatt_notify_uuid(bt_hci_conn_lookup_handle(cx->getHandle()),
                                 &BLELNBase::DATA_TX_UUID.uuid, ln_svc.attrs,
                                 encrypted.data(), encrypted.size());
    return true;
}

ssize_t BLELNServer::onDataWrite(struct bt_conn *conn, [[maybe_unused]] const struct bt_gatt_attr *attr,
                                 const void *buf, uint16_t len, uint16_t offset, [[maybe_unused]] uint8_t flags) {
    if (offset != 0) {
        return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
    }

    BLELNConnCtx *cx;
    uint16_t connHandle;
    bt_hci_get_conn_handle(conn, &connHandle);

    if(!BLELNServer::getConnContext(connHandle, &cx)){
        printk("Failed locking semaphore! (onWrite)\r\n");
        return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
    }
    if (!cx) {
        printk("Received message from unknown client\r\n");
        return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
    }
    const std::string &v = std::string((char*)buf, len);

    if (v.empty()) {
        return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
    }

    instance->appendToQueue(connHandle, v);
    return len;
}

ssize_t BLELNServer::onKeyExRxWrite(struct bt_conn *conn, [[maybe_unused]] const struct bt_gatt_attr *attr,
                                    const void *buf, uint16_t len, uint16_t offset, uint8_t flags) {
    if (offset != 0) {
        return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
    }

    printk("Received keyRX\r\n");
    BLELNConnCtx *cx;
    uint16_t conH;
    bt_hci_get_conn_handle(conn, &conH);
    if(!BLELNServer::getConnContext(conH, &cx)){
        return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
    }
    if (!cx) return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);

    const std::string &v = std::string((char*)buf, len);
    // [ver=1][cliPub:65][cliNonce:12]
    if (v.size()!=1+65+12 || (uint8_t)v[0]!=1) { printk("[HX] bad packet\r\n"); return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY); }

    bool r= cx->getEncData()->deriveSessionKey((const uint8_t*)&v[1],
                                               (const uint8_t*)&v[1+65],
                                               (const uint8_t*)instance->g_psk_salt,
                                               instance->g_epoch);

    if (!r ) {
        printk("[HX] derive failed\r\n"); return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
    }
    cx->setSessionReady(true);
    sendEncrypted(cx, "$HDSH,OK");

    return len;
}

void BLELNServer::onKeyExTxSubscribe(const struct bt_gatt_attr *attr, uint16_t value) {
    bool enabled = (value == BT_GATT_CCC_NOTIFY);
    printk("CCC %p notify %s\n", attr, enabled ? "ON" : "OFF");

    if(enabled) {
        printk("Client subscribed for KeyTX\r\n");
        BLELNConnCtx *cx;

        uint16_t conH;
        bt_hci_get_conn_handle(current_conn, &conH);
        if (!getConnContext(conH, &cx) or (cx == nullptr)){
            printk("Failed on getConnContext for conH %d", conH);
            return;
        }

        if (cx->isSendKeyNeeded()) {
            printk("Sending key to client");
            instance->sendKeyToClient(cx);
        }
    } else {
        printk("Client unsubscribed for KeyTX\r\n");
    }
}

bool BLELNServer::sendEncrypted(int i, const std::string &msg) {
    if(k_mutex_lock(&clisMtx, K_MSEC(100)) != 0)
        return false;

    if(i<connCtxs.size()){
        sendEncrypted(connCtxs[i].get(), msg);
    }
    k_mutex_unlock(&clisMtx);

    return true;
}

bool BLELNServer::sendEncrypted(const std::string &msg) {
    for(int i=0; i<instance->connCtxs.size(); i++){
        if(!instance->sendEncrypted(i, msg)) return false;
    }

    return true;
}

void BLELNServer::stop() {
    //TODO: NimBLEDevice::stopAdvertising();
    // Stop rx worker
    instance->runRxWorker= false;

    // Disconnect every client

    // Remove callbacks

    // Clear context list
    instance->connCtxs.clear();

    // Reset pointer and callback
}

void BLELNServer::setOnMessageReceivedCallback(std::function<void(uint16_t cliH, const std::string& msg)> cb) {
    instance->onMsgReceived= std::move(cb);
}

bool BLELNServer::sendEncrypted(uint16_t h, const std::string &msg) {
    BLELNConnCtx *connCtx= nullptr;
    getConnContext(h, &connCtx);

    if(connCtx!= nullptr) {
        if (k_mutex_lock(&instance->clisMtx, K_MSEC(100)) != 0)
            return false;
        sendEncrypted(connCtx, msg);
        k_mutex_unlock(&instance->clisMtx);
        return true;
    }

    return false;
}

bool BLELNServer::noClientsConnected() {
    uint8_t clisCnt=1;

    if(k_mutex_lock(&clisMtx, K_MSEC(50))==0){
        clisCnt= connCtxs.size();
        k_mutex_unlock(&clisMtx);
    }

    return clisCnt==0;
}

void BLELNServer::connected_cb(struct bt_conn *conn, uint8_t err) {
    BLELNConnCtx* c = nullptr;
    uint16_t connHandle;
    bt_hci_get_conn_handle(conn, &connHandle);

    printk("New client wants to connect...\r\n");

    if(!BLELNServer::getConnContext(connHandle, &c)){
        printk("Failed searching for context!\r\n");
        return;
    }

    if (c == nullptr) {
        printk("Creating new ConnCtx\r\n");
        if(k_mutex_lock(&instance->clisMtx, K_MSEC(100)) != 0){
            printk("Failed locking semaphore! (create new client)!\r\n");
            return;
        }
        instance->connCtxs.emplace_back(std::make_unique<BLELNConnCtx>(connHandle));
        c = (instance->connCtxs.end() - 1).base()->get();
        k_mutex_unlock(&instance->clisMtx);

        printk("New client handle: %d\r\n", c->getHandle());
    }
    if (!c->getEncData()->makeServerKeys()) {
        printk("ECDH keygen fail\r\n");
        return;
    }

    current_conn = bt_conn_ref(conn);
    bt_le_adv_stop();
}

void BLELNServer::disconnected_cb(struct bt_conn *conn, uint8_t reason) {
    int removeIdx = -1;
    uint16_t connHandle;
    bt_hci_get_conn_handle(conn, &connHandle);

    if(k_mutex_lock(&instance->clisMtx, K_MSEC(100)) != 0){
        printk("Failed locking semaphore! (onDisconnect)\r\n");
        return;
    }
    for (int i=0; i < instance->connCtxs.size(); i++){
        if (instance->connCtxs[i]->getHandle() == connHandle){
            removeIdx = i;
            break;
        }
    }
    if(removeIdx>=0){
        instance->connCtxs.erase(instance->connCtxs.begin() + removeIdx);
    }

    if (current_conn) {
        bt_conn_unref(current_conn);
        current_conn = nullptr;
    }
    k_mutex_unlock(&instance->clisMtx);
    startAdvertising(instance->advName.c_str());
}
