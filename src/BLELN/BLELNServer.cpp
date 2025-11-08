//
// Created by dkulpa on 17.08.2025.
//

#include "BLELNServer.h"

#include <utility>
#include "BLELNBase.h"

K_THREAD_STACK_DEFINE(g_rx_stack, 2560);

// --- statyczne wskaźniki do instancji (1 klient na aplikację)
static BLELNServer* instance = nullptr;

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

/* ===== CCC (włączanie notify) ===== */
static void ccc_cfg_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
    bool enabled = (value == BT_GATT_CCC_NOTIFY);
    printk("CCC %p notify %s\n", attr, enabled ? "ON" : "OFF");
}

static ssize_t generic_write(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                             const void *buf, uint16_t len, uint16_t offset, uint8_t flags)
{
    ARG_UNUSED(conn);
    ARG_UNUSED(flags);

    /* W prostym wariancie oczekujemy zapisu całego bufora bez offsetów */
    if (offset != 0) {
        return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
    }

    const struct bt_uuid *uuid = attr->uuid;

    if (bt_uuid_cmp(uuid, &BLELNBase::KEYEX_RX_UUID.uuid) == 0) {
        /* odebrano klucz/fragment wymiany */
        printk("KEYEX_RX %uB\n", len);
        /* TODO: Twoja logika KeyEx */
        return len;
    }

    if (bt_uuid_cmp(uuid, &BLELNBase::DATA_RX_UUID.uuid) == 0) {
        /* odebrano dane od klienta */
        printk("DATA_RX %uB\n", len);
        /* TODO: Twoja logika danych przychodzących */
        return len;
    }

    return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
}

static ssize_t data_tx_read(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                            void *buf, uint16_t len, uint16_t offset)
{
    ARG_UNUSED(conn);
    ARG_UNUSED(attr);

    k_mutex_lock(&data_tx_mtx, K_FOREVER);
    ssize_t out = bt_gatt_attr_read(conn, attr, buf, len, offset,
                                    data_tx_buf, data_tx_len);
    k_mutex_unlock(&data_tx_mtx);
    return out;
}


BT_GATT_SERVICE_DEFINE(ln_svc,
                       BT_GATT_PRIMARY_SERVICE(&BLELNBase::SERVICE_UUID),

                       BT_GATT_CHARACTERISTIC(&BLELNBase::KEYEX_TX_UUID.uuid,
                                              BT_GATT_CHRC_NOTIFY,
                                              BT_GATT_PERM_NONE,
                                              nullptr, nullptr, nullptr),
                       BT_GATT_CCC(ccc_cfg_changed, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),

                       BT_GATT_CHARACTERISTIC(&BLELNBase::KEYEX_RX_UUID.uuid,
                                              BT_GATT_CHRC_WRITE,
                                              BT_GATT_PERM_WRITE,
                                              nullptr, generic_write, nullptr),

                       BT_GATT_CHARACTERISTIC(&BLELNBase::DATA_TX_UUID.uuid,
                                              BT_GATT_CHRC_READ | BT_GATT_CHRC_NOTIFY,
                                              BT_GATT_PERM_READ,
                                              data_tx_read, nullptr, nullptr),
                       BT_GATT_CCC(ccc_cfg_changed, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),

                       BT_GATT_CHARACTERISTIC(&BLELNBase::DATA_RX_UUID.uuid,
                                              BT_GATT_CHRC_WRITE,
                                              BT_GATT_PERM_WRITE,
                                              nullptr, generic_write, nullptr)
);

void BLELNServer::start(const uint8_t *name, const std::string &uuid) {
    if(instance == nullptr)
        BLELNServer::init();

    instance->serviceUUID= uuid;

    // BT on
    int err = bt_enable(nullptr);
    if (err) {
        printk("bt_enable err=%d\r\n", err);
        return;
    }

    err = settings_load();   // WAŻNE!
    printk("settings_load -> %d\n\r", err);


    k_mutex_init(&instance->clisMtx);
    k_mutex_init(&instance->keyExTxMtx);
    k_mutex_init(&instance->txMtx);
    k_fifo_init(&instance->rx_fifo);

    instance->runRxWorker= true;
    k_thread_create(&instance->rx_thread, g_rx_stack, K_THREAD_STACK_SIZEOF(g_rx_stack),
                    [](void* p1, void*, void*) {
                        static_cast<BLELNServer*>(p1)->rxWorker();
                    },
                    this, nullptr, nullptr, K_PRIO_COOP(8), 0, K_NO_WAIT);


    BLELNBase::load_or_init_psk(prefs, g_psk_salt, &g_epoch);
    BLELNBase::rng_init();


    /* Reklama: flage + UUID usługi */
    struct bt_data ad[] = {
            BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
            BT_DATA_BYTES(BT_DATA_UUID128_ALL, /* 16B little-endian */
                          0xef,0xcd,0xab,0x90,0x78,0x56,0x34,0x12, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
            /* ↑ tu wstaw surowe 128-bit (LSB→MSB) swojej usługi; powyżej pasuje do SVC_UUID */
    };

    /* Scan Response z nazwą urządzenia */
    struct bt_data sd[] = {
            BT_DATA(BT_DATA_NAME_COMPLETE, name, (uint8_t)strlen((const char*)name)),
    };



    NimBLEDevice::init(name);
    NimBLEDevice::setMTU(247);

    // Security: bonding + MITM + LE Secure Connections
    NimBLEDevice::setSecurityAuth(false, false, false);

    srv = NimBLEDevice::createServer();
    srv->setCallbacks(this);

    auto* svc = srv->createService(serviceUUID);

    chKeyExTx = svc->createCharacteristic(BLELNBase::KEYEX_TX_UUID, NIMBLE_PROPERTY::NOTIFY);
    chKeyExRx = svc->createCharacteristic(BLELNBase::KEYEX_RX_UUID, NIMBLE_PROPERTY::WRITE);// | NIMBLE_PROPERTY::WRITE_ENC | NIMBLE_PROPERTY::WRITE_AUTHEN);
    chDataTx  = svc->createCharacteristic(BLELNBase::DATA_TX_UUID,  NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::NOTIFY);// | NIMBLE_PROPERTY::READ_ENC);
    chDataRx  = svc->createCharacteristic(BLELNBase::DATA_RX_UUID,  NIMBLE_PROPERTY::WRITE);// | NIMBLE_PROPERTY::WRITE_ENC | NIMBLE_PROPERTY::WRITE_AUTHEN);

    chKeyExTx->setCallbacks(new KeyExTxClb(this));
    chKeyExRx->setCallbacks(new KeyExRxClb(this));
    chDataRx->setCallbacks(new DataRxClb(this));

    svc->start();

    auto* adv = NimBLEDevice::getAdvertising();
    adv->setName(name);
    adv->addServiceUUID(serviceUUID);
    adv->enableScanResponse(true);

    NimBLEDevice::startAdvertising();

    g_lastRotateMs = millis();
}


bool BLELNServer::getConnContext(uint16_t h, BLELNConnCtx** ctx) {
    *ctx = nullptr;

    if(k_mutex_lock(&clisMtx, K_MSEC(100))!=0)
        return false;

    for (auto &c : connCtxs){
        if (c.getHandle() == h){
            *ctx = &c;
            break;
        }
    }
    k_mutex_unlock(&clisMtx);

    return true;
}

void BLELNServer::setChDataTx(const std::string &s) {
    chDataTx->setValue(s.c_str());
}

void BLELNServer::notifyChDataTx() {
    chDataTx->notify();
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
        chKeyExTx->setValue(keyex);
        chKeyExTx->notify(cx->getHandle());
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
                free(node->buf);
                free(node);
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

                free(node->buf);
                free(node);
            }
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

    chDataTx->setValue(encrypted);
    chDataTx->notify(cx->getHandle());
    auto *attr= static_cast<bt_gatt_attr *>(malloc(sizeof(struct bt_gatt_attr)));

    bt_gatt_attr_get_handle()

    bt_gatt_notify_uuid(bt_hci_conn_lookup_handle(cx->getHandle()), &BLELNBase::SERVICE_UUID.uuid,
                        attr, encrypted.data(), encrypted.size());
    return true;
}

void BLELNServer::onDataWrite(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                              const void *buf, uint16_t len, uint16_t offset, uint8_t flags) {
    BLELNConnCtx *cx;
    uint16_t connHandle;
    bt_hci_get_conn_handle(conn, &connHandle);

    if(!server_sltn->getConnContext(connHandle, &cx)){
        printk("Failed locking semaphore! (onWrite)\r\n");
        return;
    }
    if (!cx) {
        printk("Received message from unknown client\r\n");
        return;
    }
    const std::string &v = std::string((char*)buf, len);

    if (v.empty()) {
        return;
    }

    server_sltn->appendToQueue(connHandle, v);
}

void BLELNServer::onKeyExRxWrite(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                                 void *buf, uint16_t len, uint16_t offset) {
    printk("Received keyRX\r\n");
    BLELNConnCtx *cx;
    uint16_t conH;
    bt_hci_get_conn_handle(conn, &conH);
    if(!server_sltn->getConnContext(conH, &cx)){
        return;
    }
    if (!cx) return;

    const std::string &v = std::string((char*)buf, len);
    // [ver=1][cliPub:65][cliNonce:12]
    if (v.size()!=1+65+12 || (uint8_t)v[0]!=1) { printk("[HX] bad packet\r\n"); return; }

    bool r= cx->getEncData()->deriveSessionKey(&BLELNBase::ctr_drbg, (const uint8_t*)&v[1],
                                               (const uint8_t*)&v[1+65], g_psk_salt,
                                               g_epoch);

    if (!r ) {
        printk("[HX] derive failed\r\n"); return;
    }
    cx->setSessionReady(true);
    sendEncrypted(cx, "$HDSH,OK");
}

void BLELNServer::onKeyExTxSubscribe(NimBLECharacteristic *pCharacteristic, NimBLEConnInfo &connInfo, uint16_t subValue) {
    if(subValue>0) {
        printk("Client subscribed for KeyTX\r\n");
        BLELNConnCtx *cx;
        if (!getConnContext(connInfo.getConnHandle(), &cx) or (cx == nullptr)) return;

        if (cx->isSendKeyNeeded()) {
            sendKeyToClient(cx);
        }
    } else {
        printk("Client unsubscribed for KeyTX\r\n");
    }
}

bool BLELNServer::sendEncrypted(int i, const std::string &msg) {
    if(k_mutex_lock(&clisMtx, K_MSEC(100)) == 000)
        return false;

    if(i<connCtxs.size()){
        sendEncrypted(&connCtxs[i], msg);
    }
    k_mutex_unlock(&clisMtx);

    return true;
}

bool BLELNServer::sendEncrypted(const std::string &msg) {
    for(int i=0; i<connCtxs.size(); i++){
        if(!sendEncrypted(i, msg)) return false;
    }

    return true;
}

void BLELNServer::stop() {
    NimBLEDevice::stopAdvertising();
    // Stop rx worker
    runRxWorker= false;

    if(g_rxQueue)
        xQueueReset(g_rxQueue);

    // Disconnect every client
    if (srv!=nullptr) {
        if(xSemaphoreTake(clisMtx, pdMS_TO_TICKS(300))==pdTRUE) {
            for (auto &c: connCtxs) {
                srv->disconnect(c.getHandle());
            }
            k_mutex_unlock(&clisMtx);
        }
    }

    // Remove callbacks
    if (chKeyExTx)
        chKeyExTx->setCallbacks(nullptr);
    if (chKeyExRx)
        chKeyExRx->setCallbacks(nullptr);
    if (chDataRx)
        chDataRx ->setCallbacks(nullptr);



    // Clear context list
    connCtxs.clear();

    // Reset pointer and callback
    chKeyExTx = nullptr;
    chKeyExRx = nullptr;
    chDataTx  = nullptr;
    chDataRx  = nullptr;
    srv       = nullptr;
    onMsgReceived = nullptr;

    NimBLEDevice::deinit(true);
}

void BLELNServer::setOnMessageReceivedCallback(std::function<void(uint16_t cliH, const std::string& msg)> cb) {
    onMsgReceived= std::move(cb);
}

bool BLELNServer::sendEncrypted(uint16_t h, const std::string &msg) {
    BLELNConnCtx *connCtx= nullptr;
    getConnContext(h, &connCtx);

    if(connCtx!= nullptr) {
        if (k_mutex_lock(&clisMtx, K_MSEC(100)) != 0)
            return false;
        sendEncrypted(connCtx, msg);
        k_mutex_unlock(&clisMtx);
        return true;
    }

    return false;
}

void BLELNServer::startOtherServerSearch(uint32_t durationMs, const std::string &otherUUID, const std::function<void(bool)>& onResult) {
    scanning = true;
    onScanResult= onResult;
    searchedUUID= otherUUID;
    auto* scan=NimBLEDevice::getScan();
    scan->setScanCallbacks(this, false);
    scan->setActiveScan(true);
    scan->start(durationMs, false, false);
}

void BLELNServer::onResult(const NimBLEAdvertisedDevice *advertisedDevice) {
    if (advertisedDevice->isAdvertisingService(NimBLEUUID(searchedUUID))) {
        scanning = false;
        if(onScanResult){
            onScanResult(true);
        }
    }
}

void BLELNServer::onScanEnd(const NimBLEScanResults &scanResults, int reason) {
    scanning = false;
    if(onScanResult){
        onScanResult(false);
    }
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

    if(!server_sltn->getConnContext(connHandle, &c)){
        printk("Failed searching for context!\r\n");
        return;
    }

    if (c == nullptr) {
        printk("Creating new ConnCtx\r\n");
        if(k_mutex_lock(&server_sltn->clisMtx, K_MSEC(100)) == 0){
            printk("Failed locking semaphore! (create new client)!\r\n");
            return;
        }
        server_sltn->connCtxs.emplace_back(connHandle);
        c = (server_sltn->connCtxs.end() - 1).base();
        k_mutex_unlock(&server_sltn->clisMtx);

        printk("New client handle: %d\r\n", c->getHandle());
    }
    if (!c->getEncData()->makeServerKeys(&BLELNBase::ctr_drbg)) {
        printk("ECDH keygen fail\r\n");
        return;
    }


    NimBLEDevice::startAdvertising();
}

void BLELNServer::disconnected_cb(struct bt_conn *conn, uint8_t reason) {
    int removeIdx = -1;
    uint16_t connHandle;
    bt_hci_get_conn_handle(conn, &connHandle);

    if(k_mutex_lock(&server_sltn->clisMtx, K_MSEC(100)) != 0){
        printk("Failed locking semaphore! (onDisconnect)\r\n");
        return;
    }
    for (int i=0; i < server_sltn->connCtxs.size(); i++){
        if (server_sltn->connCtxs[i].getHandle() == connHandle)){
            removeIdx = i;
            break;
        }
    }
    if(removeIdx>=0){
        server_sltn->connCtxs.erase(server_sltn->connCtxs.begin() + removeIdx);
    }
    k_mutex_unlock(&server_sltn->clisMtx);
    NimBLEDevice::startAdvertising();
}

int BLELNServer::start_advertising(const char *name)
{
    /* Reklama: flage + UUID usługi */
    struct bt_data ad[] = {
            BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
            BT_DATA_BYTES(BT_DATA_UUID128_ALL, /* 16B little-endian */
                          0xef,0xcd,0xab,0x90,0x78,0x56,0x34,0x12, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
            /* ↑ tu wstaw surowe 128-bit (LSB→MSB) swojej usługi; powyżej pasuje do SVC_UUID */
    };

    /* Scan Response z nazwą urządzenia */
    struct bt_data sd[] = {
            BT_DATA(BT_DATA_NAME_COMPLETE, name, (uint8_t)strlen(name)),
    };

#if defined(CONFIG_BT_DEVICE_NAME_DYNAMIC)
    bt_set_name(name);
#endif

    const struct bt_le_adv_param *param = BT_LE_ADV_PARAM(
            BT_LE_ADV_OPT_CONN,
            0x00A0, /* min interval 100 ms */
            0x00F0, /* max interval 150 ms */
            nullptr);

    return bt_le_adv_start(param, ad, ARRAY_SIZE(ad), sd, ARRAY_SIZE(sd));
}


