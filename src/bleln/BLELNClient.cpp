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

#include "BLELNClient.h"
#include "Encryption.h"
#include "BLELNConnCtx.h"
#include "SuperString.h"
#include <cstring>

K_THREAD_STACK_DEFINE(g_client_rx_stack, 2272);


static BLELNClient* instance = nullptr;

static const struct bt_conn_auth_cb s_auth_cb = {
        .passkey_entry = BLELNClient::auth_passkey_entry,
        .cancel        = BLELNClient::auth_cancel,
};

static struct bt_conn_cb s_conn_cb = {
        .connected    = BLELNClient::connected_cb,
        .disconnected = BLELNClient::disconnected_cb,
};

struct AdvMatchCtx {
    bool* has;
    const bt_uuid_128* uuid;
};

extern "C" bool adv_parse_uuid128_cb(struct bt_data* data, void* user_data) {
    auto* c = static_cast<AdvMatchCtx*>(user_data);
    if (!c || !c->has || !c->uuid) return true;

    if (data->type != BT_DATA_UUID128_ALL && data->type != BT_DATA_UUID128_SOME) {
        return true;
    }

    const uint8_t* p = static_cast<const uint8_t*>(data->data);
    size_t len = data->data_len;
    while (len >= 16) {
        if (memcmp(p, c->uuid->val, 16) == 0) {
            *(c->has) = true;
            return false;
        }
        p += 16;
        len -= 16;
    }
    return true;
}

// ===== Utils =====
bool BLELNClient::parse_uuid128(const std::string& s, bt_uuid_128* out) {
    if (s.size() != 36) return false;
    uint8_t bytes[16]{};
    auto hex = [](char c)->int{
        if (c>='0'&&c<='9') return c-'0';
        if (c>='a'&&c<='f') return 10+(c-'a');
        if (c>='A'&&c<='F') return 10+(c-'A');
        return -1;
    };
    const int map[16][2] = {
            {0,1},{2,3},{4,5},{6,7},     // time_low
            {9,10},{11,12},              // time_mid
            {14,15},{16,17},             // time_hi
            {19,20},{21,22},             // clock_seq
            {24,25},{26,27},{28,29},{30,31},{32,33},{34,35} // node
    };
    for (int i=0;i<16;i++) {
        int h = hex(s[ map[i][0] ]);
        int l = hex(s[ map[i][1] ]);
        if (h<0||l<0) return false;
        bytes[i] = (uint8_t)((h<<4)|l);
    }
    for (int i=0;i<16;i++) out->val[i] = bytes[15 - i];
    out->uuid.type = BT_UUID_TYPE_128;
    return true;
}


BLELNClient::BLELNClient(const uint8_t *certSign, const uint8_t *manuPubKey, const uint8_t *myPrivateKey,
                         const uint8_t *myPublicKey, const std::string &userId) :
        authStore(certSign, manuPubKey, myPrivateKey, myPublicKey, userId){

}

void BLELNClient::init(const uint8_t *certSign, const uint8_t *manuPubKey, const uint8_t *myPrivateKey,
                       const uint8_t *myPublicKey, const std::string &userId) {
    instance= new BLELNClient(certSign, manuPubKey, myPrivateKey, myPublicKey, userId);
    Encryption::randomizer_init();
}


void BLELNClient::deinit() {
    delete instance;
}


void BLELNClient::start(const std::string& name, std::function<void(const std::string&)> onServerResponse) {
    if(instance == nullptr)
        return;

    bt_conn_cb_register(&s_conn_cb);
    bt_conn_auth_cb_register(&s_auth_cb);

    bt_le_oob oob{};
    bt_set_name(name.c_str());

    k_fifo_init(&instance->workerActionQueue);
    instance->runWorker = true;
    k_thread_create(&instance->rx_thread, g_client_rx_stack, K_THREAD_STACK_SIZEOF(g_client_rx_stack),
                    [](void* p1, void*, void*) {
                        instance->worker();
                    },
                    nullptr, nullptr, nullptr, K_PRIO_COOP(8), 0, K_NO_WAIT);

    instance->onMsgRx = std::move(onServerResponse);
}

void BLELNClient::stop() {

}

void BLELNClient::startServerSearch(uint32_t durationMs,
                                    const std::string& serverUUID,
                                    const std::function<void(const bt_addr_le_t* addr)>& onResult) {
    instance->onScanResult = onResult;
    instance->scanning = true;

    static const struct bt_le_scan_param params = {
            .type       = BT_LE_SCAN_TYPE_ACTIVE,
            .options    = BT_LE_SCAN_OPT_NONE,
            .interval   = 0x0060, // 60 * 0.625ms = 37.5ms
            .window     = 0x0030, // 30 * 0.625ms = 18.75ms
    };

    int u=0;
    int i=0;

    int err = bt_le_scan_start(&params, BLELNClient::device_found_cb_new);
    if (err) {
        printk("scan start err=%d\r\n", err);
        instance->scanning = false;
        if (instance->onScanResult) instance->onScanResult(nullptr);
        return;
    }

    k_work_delayable timeout_work{};
    k_work_init_delayable(&timeout_work, [](k_work* w){});
    k_sleep(K_MSEC(durationMs));
    if (instance->scanning) {
        bt_le_scan_stop();
        instance->scanning = false;
        if (instance->onScanResult)
            instance->onScanResult(nullptr);
    }
}

void BLELNClient::beginConnect(const bt_addr_le_t* addr, const std::function<void(bool, int)>& onConnectResult) {
    instance->onConRes = onConnectResult;

    bt_conn_le_create_param create_param = {
            .options = BT_CONN_LE_OPT_NONE,
            .interval = BT_GAP_INIT_CONN_INT_MIN,
            .window   = BT_GAP_SCAN_FAST_WINDOW,
            .interval_coded = 0,
            .window_coded   = 0,
            .timeout = 0,
    };
    bt_le_conn_param conn_param = {
            .interval_min = 24,
            .interval_max = 40,
            .latency = 0,
            .timeout = 400
    };

    int err = bt_conn_le_create(addr, &create_param, &conn_param, &instance->conn);
    if (err) {
        if (instance->onConRes) instance->onConRes(false, err);
        return;
    }
}

bool BLELNClient::sendEncrypted(const std::string& msg) {
    instance->appendActionToQueue(BLELN_WORKER_ACTION_SEND_MESSAGE, 0,
                        reinterpret_cast<const uint8_t *>(msg.data()), msg.size());
    return true;
}

bool BLELNClient::isScanning() { return instance->scanning; }

bool BLELNClient::isConnected() { return instance->conn != nullptr; }

void BLELNClient::appendActionToQueue(uint8_t type, uint16_t conH, const uint8_t *data, size_t dataLen) {
    uint8_t *heapBuf= nullptr;

    if(data!= nullptr) {
        heapBuf = (uint8_t*)k_malloc(dataLen);
        if (!heapBuf) return;
        memcpy(heapBuf, data, dataLen);
    } else {
        dataLen=0;
    }

    auto* pkt= (BLELNWorkerAction*) k_malloc(sizeof(BLELNWorkerAction));
    if (!pkt) { k_free(heapBuf); return; }

    pkt->type= type;
    pkt->connH= conH;
    pkt->dlen= dataLen;
    pkt->d= heapBuf;
    k_fifo_put(&workerActionQueue, pkt);
}

void BLELNClient::worker() {
    while(runWorker){
        auto *action = static_cast<BLELNWorkerAction *>(k_fifo_get(&workerActionQueue, K_MSEC(1)));

        if(action) {
            if (action->type == BLELN_WORKER_ACTION_REGISTER_CONNECTION) {
                worker_registerConnection(action->connH);
            } else if(action->type == BLELN_WORKER_ACTION_SERVICE_DISCOVERED){
                memset(&sub_keyex, 0, sizeof(sub_keyex));
                sub_keyex.ccc_handle = BT_GATT_AUTO_DISCOVER_CCC_HANDLE;
                sub_keyex.value_handle = h_keyex_tx;
                sub_keyex.notify = notify_keyex_cb;
                sub_keyex.end_handle= h_data_tx;
                sub_keyex.value = BT_GATT_CCC_NOTIFY;
                sub_keyex.disc_params= &keyex_ccc_disc_params;
                int r= bt_gatt_subscribe(conn, &sub_keyex);
                printk("Subscribe key ex: %d\r\n", r);

                memset(&sub_data, 0, sizeof(sub_data));
                sub_data.ccc_handle = BT_GATT_AUTO_DISCOVER_CCC_HANDLE;
                sub_data.value_handle = h_data_tx;
                sub_data.notify = notify_data_cb;
                sub_data.value = BT_GATT_CCC_NOTIFY;
                sub_data.end_handle= 0xffff;
                sub_data.disc_params= &data_ccc_disc_params;
                r= bt_gatt_subscribe(conn, &sub_data);
                printk("Subscribe data: %d\r\n", r);

                connCtx->setState(BLELNConnCtx::State::WaitingForKey);
            } else if (action->type == BLELN_WORKER_ACTION_DELETE_CONNECTION) {
                worker_deleteConnection();
            } else if(action->type==BLELN_WORKER_ACTION_SEND_MESSAGE){
                worker_sendMessage(action->d, action->dlen);
            } else if(action->type==BLELN_WORKER_ACTION_PROCESS_KEY_RX){
                worker_processKeyRx(action->d, action->dlen);
            } else if(action->type==BLELN_WORKER_ACTION_PROCESS_DATA_RX){
                worker_processDataRx(action->d, action->dlen);
            }

            k_free(action->d);
            k_free(action);
        }

        if(lastWaterMarkPrint+10000 < k_uptime_get()) {
            size_t unused_bytes = 0;
            int ret = k_thread_stack_space_get(k_current_get(), &unused_bytes);
            if(ret == 0){
                printk("[D] BLELNClient - stack free: %u\n\r", unused_bytes);
            }

            lastWaterMarkPrint= k_uptime_get();
        }

        // Pause task
        if(k_fifo_is_empty(&workerActionQueue)){
            k_sleep(K_MSEC(100));
        } else {
            k_sleep(K_MSEC(5));
        }
    }
}


void BLELNClient::worker_registerConnection(uint16_t h) {
    if (onConRes) {
        onConRes(true, 0);
    }
    printk("[D] BLELNClient - Client connected\n");
    connCtx = new BLELNConnCtx(h);

    if(discover()){

    } else {
        printk("[E] BLELNClient - discover failed\n");
    }
}

void BLELNClient::worker_deleteConnection() {
    if (connCtx) {
        delete connCtx;
        connCtx = nullptr; // Ważne!
    }
}

void BLELNClient::worker_sendMessage(uint8_t *data, size_t dataLen) {
    std::string msg(reinterpret_cast<char*>(data), dataLen);
    std::string encMsg;

    if(connCtx!= nullptr and connCtx->getSessionEnc()->encryptMessage(msg, encMsg)){
        int err = bt_gatt_write_without_response(conn, h_keyex_rx, encMsg.data(), encMsg.size(), false);
        if (err) {
            // TODO: Handle error
        }
    }
}

void BLELNClient::worker_processKeyRx(uint8_t *data, size_t dataLen) {
    if(connCtx!= nullptr){
        if(connCtx->getState()==BLELNConnCtx::State::WaitingForKey){
            printk("[D] BLELNClient - Received servers key\n");
            if(handshake(data, dataLen)){
                connCtx->setState(BLELNConnCtx::State::WaitingForCert);
            } else {
                printk("[E] BLELNClient - handshake failed\n");
                disconnect(BT_HCI_ERR_AUTH_FAIL);
                connCtx->setState(BLELNConnCtx::State::AuthFailed);
            }
        } else if(connCtx->getState()==BLELNConnCtx::State::WaitingForCert){
            std::string plainKeyMsg;
            if (connCtx->getSessionEnc()->decryptMessage(data, dataLen, plainKeyMsg)) {
                StringList parts= splitCsvRespectingQuotes(plainKeyMsg);
                if(parts[0]==BLELN_MSG_TITLE_CERT and parts.size()==3){

                    uint8_t gen;
                    uint8_t fMac[6];
                    uint8_t fPubKey[BLELN_DEV_PUB_KEY_LEN];
                    int friendsUserId;

                    if(authStore.verifyCert(parts[1], parts[2], &gen, fMac, 6, fPubKey, 64, &friendsUserId)){
                        connCtx->setCertData(fMac, fPubKey);
                        sendCertToServer(connCtx);
                        connCtx->setState(BLELNConnCtx::State::ChallengeResponseCli);
                    } else {
                        disconnect(BT_HCI_ERR_AUTH_FAIL);
                        connCtx->setState(BLELNConnCtx::State::AuthFailed);
                        printk("[E] BLELNClient - WaitingForCert - invalid cert\n");
                    }
                } else {
                    printk("[E] BLELNClient - WaitingForCert - wrong message\n");
                    disconnect(BT_HCI_ERR_AUTH_FAIL);
                    connCtx->setState(BLELNConnCtx::State::AuthFailed);
                }
            } else {
                disconnect(BT_HCI_ERR_AUTH_FAIL);
                connCtx->setState(BLELNConnCtx::State::AuthFailed);
            }
        } else if(connCtx->getState()==BLELNConnCtx::State::ChallengeResponseCli) {
            std::string plainKeyMsg;
            if (connCtx->getSessionEnc()->decryptMessage(data, dataLen, plainKeyMsg)) {
                StringList parts = splitCsvRespectingQuotes(plainKeyMsg);
                if (parts[0] == BLELN_MSG_TITLE_CHALLENGE_RESPONSE_NONCE and parts.size() == 2) {
                    sendChallengeNonceSign(connCtx, parts[1]);
                    connCtx->setState(BLELNConnCtx::State::ChallengeResponseSer);
                } else {
                    disconnect(BT_HCI_ERR_AUTH_FAIL);
                    connCtx->setState(BLELNConnCtx::State::AuthFailed);
                }
            } else {
                disconnect(BT_HCI_ERR_AUTH_FAIL);
                connCtx->setState(BLELNConnCtx::State::AuthFailed);
            }
        } else if(connCtx->getState()==BLELNConnCtx::State::ChallengeResponseSer) {
            std::string plainKeyMsg;
            if (connCtx->getSessionEnc()->decryptMessage(data, dataLen, plainKeyMsg)) {
                StringList parts = splitCsvRespectingQuotes(plainKeyMsg);
                if (parts[0] == BLELN_MSG_TITLE_CHALLENGE_RESPONSE_ANSW and parts.size() == 2) {
                    uint8_t nonceSign[BLELN_NONCE_SIGN_LEN];
                    Encryption::base64Decode(parts[1], nonceSign, BLELN_NONCE_SIGN_LEN);
                    if(connCtx->verifyChallengeResponseAnswer(nonceSign)){
                        std::string msg=BLELN_MSG_TITLE_AUTH_OK;
                        msg.append(",1");
                        std::string encMsg;
                        if(connCtx->getSessionEnc()->encryptMessage(msg, encMsg)) {
                            connCtx->setState(BLELNConnCtx::State::Authorised);
                            printk("[D] BLELNClient - auth success\n");
                            printk("[D] BLELNClient - client %d live for %llu ms\r\n", connCtx->getHandle(), connCtx->getTimeOfLife());
                            int err = bt_gatt_write_without_response(conn, h_keyex_rx, encMsg.data(), encMsg.size(), false);
                            if (err) {
                                // TODO: Handle error
                            }
                        } else {
                            printk("[E] BLELNClient - failed encrypting cert msg\n");
                        }
                    } else {
                        printk("[E] BLELNClient - ChallengeResponseSeri - invalid sign\n");
                        disconnect(BT_HCI_ERR_AUTH_FAIL);
                        connCtx->setState(BLELNConnCtx::State::AuthFailed);
                    }
                } else {
                    disconnect(BT_HCI_ERR_AUTH_FAIL);
                    connCtx->setState(BLELNConnCtx::State::AuthFailed);
                }
            } else {
                disconnect(BT_HCI_ERR_AUTH_FAIL);
                connCtx->setState(BLELNConnCtx::State::AuthFailed);
            }
        }
    }
}

void BLELNClient::worker_processDataRx(uint8_t *data, size_t dataLen) {
    if(connCtx!= nullptr and connCtx->getSessionEnc()->getSessionId() != 0) {
        if(connCtx->getState()==BLELNConnCtx::State::Authorised) {
            if (dataLen >= 4 + 12 + 16) {
                std::string plain;
                if (connCtx->getSessionEnc()->decryptMessage(data, dataLen, plain)) {
                    if (onMsgRx) {
                        onMsgRx(plain);
                    }
                }
            }
        } else {
            disconnect(BT_HCI_ERR_REMOTE_USER_TERM_CONN);
        }
    }
}

/*** Connection context not protected! */
void BLELNClient::sendChallengeNonceSign(BLELNConnCtx *cx, const std::string &nonceB64) {
    uint8_t nonceRaw[BLELN_TEST_NONCE_LEN];             // Servers nonce raw bytes
    uint8_t friendsNonceSign[BLELN_NONCE_SIGN_LEN];     // Servers nonce sing I have created

    // Sign nonce
    Encryption::base64Decode(nonceB64, nonceRaw, BLELN_TEST_NONCE_LEN);
    authStore.signData(nonceRaw, BLELN_TEST_NONCE_LEN, friendsNonceSign);

    // Create clients nonce
    cx->generateTestNonce();
    std::string myNonceB64= cx->getTestNonceBase64();

    // Create BLE message
    std::string msg= BLELN_MSG_TITLE_CHALLENGE_RESPONSE_ANSW_AND_NONCE;
    std::string friendsNonceSignB64= Encryption::base64Encode(friendsNonceSign, BLELN_NONCE_SIGN_LEN);
    msg.append(",").append(friendsNonceSignB64);
    msg.append(",").append(myNonceB64);

    std::string encMsg;
    if(cx->getSessionEnc()->encryptMessage(msg, encMsg)) {
        int err = bt_gatt_write_without_response(conn, h_keyex_rx, encMsg.data(), encMsg.size(), false);
        if (err) {
            // TODO: Handle error
        }
    } else {
        printk("[E] BLELNClient - failed encrypting cert msg\n");
    }
}

/*** Connection context not protected! */
void BLELNClient::sendCertToServer(BLELNConnCtx *cx) {
    std::string msg=BLELN_MSG_TITLE_CERT;
    msg.append(",").append(authStore.getSignedCert());

    std::string encMsg;
    if(cx->getSessionEnc()->encryptMessage(msg, encMsg)) {
        int err = bt_gatt_write_without_response(conn, h_keyex_rx, encMsg.data(), encMsg.size(), false);
        if (err) {
            // TODO: Handle error
        }
    } else {
        printk("[E] BLELNClient - failed encrypting cert msg\n");
    }
}

void BLELNClient::disconnect(int reason) {
    if (instance->conn && instance->sub_keyex.value_handle)
        bt_gatt_unsubscribe(instance->conn, &instance->sub_keyex);
    if (instance->conn && instance->sub_data.value_handle)
        bt_gatt_unsubscribe(instance->conn, &instance->sub_data);

    instance->h_keyex_tx = 0;
    instance->h_keyex_rx = 0;
    instance->h_data_tx = 0;
    instance->h_data_rx = 0;

    if (instance->conn) {
        bt_conn_disconnect(instance->conn, reason);
        bt_conn_unref(instance->conn);
        instance->conn = nullptr;
    }
}


void
BLELNClient::device_found_cb_new(const bt_addr_le_t *addr, int8_t rssi, uint8_t adv_type, struct net_buf_simple *buf) {
    if(instance)
        instance->handle_adv(addr, buf);
}

void BLELNClient::handle_adv(const bt_addr_le_t *addr, struct net_buf_simple *ad) {
    bool has_service = false;
    bt_data_parse(ad, [](struct bt_data *data, void *user_data){
        auto ctx = static_cast<std::pair<bool*, bt_uuid_128*>*>(user_data);
        if (data->type == BT_DATA_UUID128_ALL || data->type == BT_DATA_UUID128_SOME) {
            for (size_t off=0; off + 16 <= data->data_len; off += 16) {
                if (memcmp(data->data + off, ctx->second->val, 16) == 0) {
                    *ctx->first = true;
                    break;
                }
            }
        }
        return true;
    }, (void*)new std::pair<bool*, bt_uuid_128*>{ &has_service, (bt_uuid_128*)&BLELNBase::CLIENT_SERVICE_UUID});

    if (has_service) {
        bt_le_scan_stop();
        scanning = false;
        if (onScanResult) onScanResult(addr);
    }
}



void BLELNClient::connected_cb(struct bt_conn *c, uint8_t err) {

    if (!instance) return;
    if (err) {
        if (instance->onConRes) instance->onConRes(false, err);
        return;
    }
    if (!instance->conn) {
        uint16_t connHandle;
        bt_hci_get_conn_handle(c, &connHandle);
        // TODO: Register c object secured with mutex
        instance->conn = bt_conn_ref(c);
        instance->appendActionToQueue(BLELN_WORKER_ACTION_REGISTER_CONNECTION, connHandle, nullptr, 0);
    }
    if (instance->onConRes) instance->onConRes(true, 0);
}

void BLELNClient::disconnected_cb(struct bt_conn *c, uint8_t reason) {

    if (!instance) return;

    uint16_t connHandle;
    bt_hci_get_conn_handle(c, &connHandle);
    instance->appendActionToQueue(BLELN_WORKER_ACTION_DELETE_CONNECTION, connHandle, nullptr, 0);
    // TODO: unegister c object secured with mutex
}

void BLELNClient::auth_passkey_entry(struct bt_conn *conn) {
    bt_conn_auth_passkey_entry(conn, 123456);
}

void BLELNClient::auth_cancel(struct bt_conn *conn) {
    (void)conn;
}

uint8_t BLELNClient::discover_func(struct bt_conn *c, const struct bt_gatt_attr *attr, struct bt_gatt_discover_params *params) {
    if (!instance) return BT_GATT_ITER_STOP;
    if (!attr) {
        instance->disc_params.func = nullptr;
        return BT_GATT_ITER_STOP;
    }

    const struct bt_gatt_chrc *chrc;
    const struct bt_gatt_service_val *sval;

    uint8_t ret;
    switch (params->type) {
        case BT_GATT_DISCOVER_PRIMARY:
            sval = (const bt_gatt_service_val*)attr->user_data;
            if(bt_uuid_cmp((bt_uuid*)sval->uuid, &BLELNBase::CLIENT_SERVICE_UUID.uuid) == 0) {
                instance->disc_params.uuid = nullptr;
                instance->disc_params.type = BT_GATT_DISCOVER_CHARACTERISTIC;
                instance->disc_params.start_handle = attr->handle;
                instance->disc_params.end_handle = sval->end_handle;
                bt_gatt_discover(c, &instance->disc_params);
                ret= BT_GATT_ITER_STOP;
                break;
            } else {
                ret= BT_GATT_ITER_CONTINUE;
                break;
            }

        case BT_GATT_DISCOVER_CHARACTERISTIC:
            chrc = (const bt_gatt_chrc*)attr->user_data;
            char buf2[50];
            bt_uuid_to_str((bt_uuid*)chrc->uuid, buf2, 40);
            if (bt_uuid_cmp(((bt_uuid*)chrc->uuid), &BLELNBase::KEYEX_TX_UUID.uuid) == 0) {
                instance->h_keyex_tx = chrc->value_handle;
            } else if (bt_uuid_cmp(((bt_uuid*)chrc->uuid), &BLELNBase::KEYEX_RX_UUID.uuid) == 0) {
                instance->h_keyex_rx = chrc->value_handle;
            } else if (bt_uuid_cmp(((bt_uuid*)chrc->uuid), &BLELNBase::DATA_TX_UUID.uuid) == 0) {
                instance->h_data_tx = chrc->value_handle;
            } else if (bt_uuid_cmp(((bt_uuid*)chrc->uuid), &BLELNBase::DATA_RX_UUID.uuid) == 0) {
                instance->h_data_rx = chrc->value_handle;
            }
            ret= BT_GATT_ITER_CONTINUE;
            break;

        default:
            ret= BT_GATT_ITER_CONTINUE;
    }

    bool have_handles = instance->h_keyex_tx && instance->h_keyex_rx && instance->h_data_tx && instance->h_data_rx ;
    if (!have_handles){
        instance->appendActionToQueue(BLELN_WORKER_ACTION_SERVICE_DISCOVERED, 0, nullptr, 0);
    }
    return ret;
}

void BLELNClient::exchange_cb(struct bt_conn *conn, uint8_t err, struct bt_gatt_exchange_params *params){
    uint16_t mtu = bt_gatt_get_mtu(conn);
    printk("Current MTU: %d\n", mtu);
}

bool BLELNClient::discover() {
    if (!conn){
        printk("discover: -1\r\n");
        return false;
    }

    bt_gatt_exchange_params ex_params {.func= exchange_cb};
    bt_gatt_exchange_mtu(conn, &ex_params);

    memset(&disc_params, 0, sizeof(disc_params));
    disc_params.uuid = &BLELNBase::CLIENT_SERVICE_UUID.uuid;
    disc_params.func = discover_func;
    disc_params.type = BT_GATT_DISCOVER_PRIMARY;
    disc_params.start_handle = 0x0001;
    disc_params.end_handle = 0xffff;

    int err = bt_gatt_discover(conn, &disc_params);
    if (err) {
        printk("discover err=%d\r\n", err);
        return false;
    }

    return true;
}

uint8_t BLELNClient::notify_keyex_cb(struct bt_conn *c,
                                     struct bt_gatt_subscribe_params *params,
                                     const void *data, uint16_t length) {
    if (!instance) return BT_GATT_ITER_CONTINUE;
    if (!data || length == 0) return BT_GATT_ITER_CONTINUE;
    instance->onKeyExNotify((const uint8_t*)data, length);
    return BT_GATT_ITER_CONTINUE;
}

uint8_t BLELNClient::notify_data_cb(struct bt_conn *c,
                                    struct bt_gatt_subscribe_params *params,
                                    const void *data, uint16_t length) {
    if (!instance) return BT_GATT_ITER_CONTINUE;
    if (!data || length == 0) return BT_GATT_ITER_CONTINUE;
    instance->onDataNotify((const uint8_t *) data, length);
    return BT_GATT_ITER_CONTINUE;
}

void BLELNClient::onKeyExNotify(const uint8_t* pData, size_t length) {
    if (!pData || !length) return;
    appendActionToQueue(BLELN_WORKER_ACTION_PROCESS_KEY_RX, 0, pData, length);
}

void BLELNClient::onDataNotify(const uint8_t* pData, size_t length) {
    if (!pData || !length) return;
    appendActionToQueue(BLELN_WORKER_ACTION_PROCESS_DATA_RX, 0, pData, length);
}

bool BLELNClient::handshake(uint8_t *v, size_t vlen) {
    if (vlen!=1+4+32+65+12 || (uint8_t)v[0]!=1) {
        return false;
    }

    uint32_t s_epoch = 0;
    uint8_t  s_salt[32], s_srvPub[65], s_srvNonce[12];

    memcpy(&s_epoch,  &v[1], 4);
    memcpy(s_salt,    &v[1+4], 32);
    memcpy(s_srvPub,  &v[1+4+32], 65);
    memcpy(s_srvNonce,&v[1+4+32+65], 12);

    connCtx->getSessionEnc()->makeMyKeys();

    // [ver=1][cliPub:65][cliNonce:12]
    std::string tx;
    tx.push_back(1);
    tx.append((const char*)connCtx->getSessionEnc()->getMyPub(),65);
    tx.append((const char*)connCtx->getSessionEnc()->getMyNonce(),12);

    int err = bt_gatt_write_without_response(conn, h_keyex_rx, tx.data(), tx.size(), false);
    if (err) {
        printk("[HX] write fail err=%d\r\n", err);
        return false;
    }

    connCtx->getSessionEnc()->deriveFriendsKey(s_srvPub, s_srvNonce, s_salt, s_epoch);

    return true;
}




