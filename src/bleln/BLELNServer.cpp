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

#include "BLELNServer.h"

#include <utility>
#include "BLELNBase.h"
#include "SuperString.h"

K_THREAD_STACK_DEFINE(g_server_rx_stack, 2272)

static BLELNServer* instance = nullptr;

BLELNServer::BLELNServer(const uint8_t *certSign, const uint8_t *manuPubKey, const uint8_t *myPrivateKey,
                         const uint8_t *myPublicKey, const std::string &userId) :
        authStore(certSign, manuPubKey, myPrivateKey, myPublicKey, userId){\
}

void BLELNServer::init(const uint8_t* certSign, const uint8_t* manuPubKey, const uint8_t* myPrivateKey, const uint8_t* myPublicKey, const std::string &userId) {
    instance= new BLELNServer(certSign, manuPubKey, myPrivateKey, myPublicKey, userId);
    Encryption::randomizer_init();
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

bool BLELNServer::callbacksRegistered = false;

int BLELNServer::startAdvertising(const char *name)
{
    struct bt_data sd[] = {
            BT_DATA(BT_DATA_NAME_COMPLETE, name, (uint8_t)strlen(name)),
    };

    bt_set_name(name);


    int ret= bt_le_adv_start(param, ad, ARRAY_SIZE(ad), sd, ARRAY_SIZE(sd));
    printk("[D] Start advertising ret: %d\n", ret);

    return ret;
}


void BLELNServer::start(const char *name, const std::string &uuid) {
    if(instance == nullptr)
        return;

    instance->advName = std::string(name);
    instance->serviceUUID = uuid;

    if (!callbacksRegistered) {
        bt_conn_cb_register(&s_conn_cb);
        callbacksRegistered = true;
    }

    k_mutex_init(&instance->clisMtx);

    k_fifo_init(&instance->rx_fifo);
    instance->runWorker = true;

    k_thread_create(&instance->rx_thread, g_server_rx_stack, K_THREAD_STACK_SIZEOF(g_server_rx_stack),
                    [](void* p1, void*, void*) {
                        instance->worker();
                    },
                    nullptr, nullptr, nullptr, K_PRIO_COOP(8), 0, K_NO_WAIT);

    startAdvertising(instance->advName.c_str());
}

void BLELNServer::setOnMessageReceivedCallback(std::function<void(uint16_t cliH, const std::string& msg)> cb) {
    instance->onMsgReceived= std::move(cb);
}


bool BLELNServer::getConnContext(uint16_t h, BLELNConnCtx** ctx) {
    *ctx = nullptr;

    auto it= std::find_if(instance->connCtxs.begin(), instance->connCtxs.end(),[h](const BLELNConnCtx &c){
        return c.getHandle()==h;
    });

    if(it!=instance->connCtxs.end()){
        *ctx= &(*it);
    }

    return *ctx!= nullptr;
}

bool BLELNServer::noClientsConnected() {
    uint8_t clisCnt=1;

    if(k_mutex_lock(&clisMtx, K_MSEC(50))==0){
        clisCnt= connCtxs.size();
        k_mutex_unlock(&clisMtx);
    }

    return clisCnt==0;
}

bool BLELNServer::_sendEncrypted(BLELNConnCtx *cx, const std::string &msg) {
    std::string encrypted;
    if(!cx->getSessionEnc()->encryptMessage(msg, encrypted)){
        printk("[E] BLELNServer - Encrypt failed\n");
        return false;
    }

    bt_gatt_notify_uuid(bt_hci_conn_lookup_handle(cx->getHandle()),
                        &BLELNBase::DATA_TX_UUID.uuid, ln_svc.attrs,
                        encrypted.data(), encrypted.size());
    return true;
}

/*** Multithreading safe */
bool BLELNServer::sendEncrypted(uint16_t h, const std::string &msg) {
    auto* heapBuf = (uint8_t*)k_malloc(msg.size());
    if (!heapBuf) return false;
    memcpy(heapBuf, msg.data(), msg.size());

    auto* pkt= (BLELNWorkerAction*) k_malloc(sizeof(BLELNWorkerAction));
    if (!pkt) { k_free(heapBuf); return false; }
    pkt->connH= h;
    pkt->type= BLELN_WORKER_ACTION_SEND_MESSAGE;
    pkt->dlen= msg.size();
    pkt->d= heapBuf;

    k_fifo_put(&instance->rx_fifo, pkt);
    return true;
}

/*** Multithreading safe */
bool BLELNServer::sendEncryptedToAll(const std::string &msg) {
    auto* heapBuf = (uint8_t*)k_malloc(msg.size());
    if (!heapBuf) return false;
    memcpy(heapBuf, msg.data(), msg.size());

    auto* pkt= (BLELNWorkerAction*) k_malloc(sizeof(BLELNWorkerAction));
    if (!pkt) { k_free(heapBuf); return false; }
    pkt->connH= UINT16_MAX;
    pkt->type= BLELN_WORKER_ACTION_SEND_MESSAGE;
    pkt->dlen= msg.size();
    pkt->d= heapBuf;

    k_fifo_put(&instance->rx_fifo, pkt);
    return true;
}

void BLELNServer::worker() {
    while(runWorker){
        auto *action = static_cast<BLELNWorkerAction *>(k_fifo_get(&rx_fifo, K_MSEC(1)));

        if (action) {
            k_mutex_lock(&clisMtx, K_FOREVER);
            if(action->type == BLELN_WORKER_ACTION_REGISTER_CONNECTION){
                worker_registerClient(action->connH);
                k_mutex_unlock(&clisMtx);
            } else if(action->type == BLELN_WORKER_ACTION_DELETE_CONNECTION){
                worker_deleteClient(action->connH);
                k_mutex_unlock(&clisMtx);
            } else if(action->type==BLELN_WORKER_ACTION_PROCESS_SUBSCRIPTION){
                k_mutex_unlock(&clisMtx);
                worker_processSubscription();
            } else if(action->type==BLELN_WORKER_ACTION_SEND_MESSAGE){
                k_mutex_unlock(&clisMtx);
                worker_sendMessage(action->connH, action->d, action->dlen);
            } else if(action->type==BLELN_WORKER_ACTION_PROCESS_KEY_RX){
                k_mutex_unlock(&clisMtx);
                worker_processKeyRx(action->connH, action->d, action->dlen);
            } else if(action->type==BLELN_WORKER_ACTION_PROCESS_DATA_RX){
                k_mutex_unlock(&clisMtx);
                worker_processDataRx(action->connH, action->d, action->dlen);
            } else {
                k_mutex_unlock(&clisMtx);
            }

            if (action->d) {
                k_free(action->d);
            }
            k_free(action);
        }



        if(lastWaterMarkPrint+10000 < k_uptime_get()) {
            size_t unused_bytes = 0;
            int ret = k_thread_stack_space_get(k_current_get(), &unused_bytes);
            if(ret == 0){
                printk("[D] BLELNServer - stack free: %u\n\r", unused_bytes);
            }

            lastWaterMarkPrint= k_uptime_get();
        }

        // Pause task
        if(k_fifo_is_empty(&rx_fifo)){
            k_sleep(K_MSEC(100));
        } else {
            k_sleep(K_MSEC(5));
        }
    }

    worker_cleanup();
    //instance->rx_thread;
}

/// *************** PRIVATE - Methods ***************

void BLELNServer::worker_registerClient(uint16_t h) {
    BLELNConnCtx *c = nullptr;

    if (!getConnContext(h, &c)) {
        connCtxs.emplace_back(h);
        c = &connCtxs.back();

        if (!c->makeSessionKey()) {
            printk("[E] BLELNServer - ECDH keygen fail\n");
        }{
            printk("[D] BLELNServer - New client context created\n");
        }
    }
}

void BLELNServer::worker_deleteClient(uint16_t h) {
    connCtxs.remove_if([h](const BLELNConnCtx& c){
        return c.getHandle()==h;
    });
}

void BLELNServer::worker_processSubscription() {
    for (auto &ctx : connCtxs) {
        if (ctx.getState() != BLELNConnCtx::State::Initialised) {
            continue;
        }
        struct bt_conn *conn = bt_hci_conn_lookup_handle(ctx.getHandle());
        if (conn) {
            const struct bt_gatt_attr *attr = &ln_svc.attrs[2];

            if (bt_gatt_is_subscribed(conn, attr, BT_GATT_CCC_NOTIFY)) {
                sendKeyToClient(&ctx);
            }

            bt_conn_unref(conn);
        }
    }
}

void BLELNServer::worker_sendMessage(uint16_t h, uint8_t *data, size_t dataLen) {
    if(h==UINT16_MAX){
        std::string m(reinterpret_cast<char*>(data), dataLen);
        for(auto & connCtx : connCtxs){
            _sendEncrypted(&connCtx,m);
        }
    } else {
        BLELNConnCtx *cx;
        if(getConnContext(h, &cx)){
            std::string m(reinterpret_cast<char*>(data), dataLen);
            _sendEncrypted(cx, m);
        }
    }
}

void BLELNServer::worker_processKeyRx(uint16_t h, uint8_t *data, size_t dataLen) {
// If new key message received
    BLELNConnCtx *cx;
    // Find context for client who sent message
    if (getConnContext(h, &cx)) {
        if (cx->getState() == BLELNConnCtx::State::WaitingForKey) {
            // If I'm waiting for clients session key
            // [ver=1][cliPub:65][cliNonce:12]
            if (dataLen != 1 + 65 + 12 || data[0] != 1) {
                printk("[E] BLELNServer - bad key packet\n");
            } else {
                // Read clients session key
                bool r = cx->getSessionEnc()->deriveFriendsKey(data + 1,
                                                               data + 1 + 65, g_psk_salt,
                                                               g_epoch);
                if (r) {
                    cx->setState(BLELNConnCtx::State::WaitingForCert);
                    sendCertToClient(cx);
                } else {
                    printk("[E] BLELNServer - derive failed\n");
                }
            }
        } else if (cx->getState() == BLELNConnCtx::State::WaitingForCert) {
            // If I'm waiting for clients certificate
            std::string plainKeyMsg;
            if (cx->getSessionEnc()->decryptMessage(data, dataLen, plainKeyMsg)) {
                StringList parts = splitCsvRespectingQuotes(plainKeyMsg);
                if (parts[0] == BLELN_MSG_TITLE_CERT and parts.size() == 3) {
                    uint8_t gen;
                    uint8_t fMac[6];
                    uint8_t fPubKey[BLELN_DEV_PUB_KEY_LEN];
                    int userId;

                    if (authStore.verifyCert(parts[1], parts[2], &gen, fMac, 6, fPubKey, 64, &userId)) {
                        if(userId==authStore.getMyUserId() or authStore.getMyUserId() ==-1) {
                            cx->setCertData(fMac, fPubKey);
                            sendChallengeNonce(cx);
                            cx->setState(BLELNConnCtx::State::ChallengeResponseCli);
                        } else {
                            disconnectClient(cx, BT_HCI_ERR_INSUFFICIENT_SECURITY);
                            cx->setState(BLELNConnCtx::State::AuthFailed);
                            printk("[W] BLELNServer - not my users client\n");
                        }
                    } else {
                        disconnectClient(cx, BT_HCI_ERR_AUTH_FAIL);
                        cx->setState(BLELNConnCtx::State::AuthFailed);
                        printk("[E] BLELNServer - WaitingForCert - invalid cert\n");
                    }
                } else {
                    printk("[E] BLELNServer - WaitingForCert - wrong message\n");
                    disconnectClient(cx, BT_HCI_ERR_AUTH_FAIL);
                    cx->setState(BLELNConnCtx::State::AuthFailed);
                }
            } else {
                disconnectClient(cx, BT_HCI_ERR_AUTH_FAIL);
                cx->setState(BLELNConnCtx::State::AuthFailed);
            }
        } else if (cx->getState() == BLELNConnCtx::State::ChallengeResponseCli) {
            // If I'm waiting for clients challenge response
            std::string plainKeyMsg;
            if (cx->getSessionEnc()->decryptMessage(data, dataLen, plainKeyMsg)) {
                StringList parts = splitCsvRespectingQuotes(plainKeyMsg);
                if (parts[0] == BLELN_MSG_TITLE_CHALLENGE_RESPONSE_ANSW_AND_NONCE and parts.size() == 3) {
                    uint8_t nonceSign[BLELN_NONCE_SIGN_LEN];
                    Encryption::base64Decode(parts[1], nonceSign, BLELN_NONCE_SIGN_LEN);
                    if (cx->verifyChallengeResponseAnswer(nonceSign)) {
                        uint8_t nonce[BLELN_TEST_NONCE_LEN];            // Clients nonce
                        uint8_t friendsNonceSign[BLELN_NONCE_SIGN_LEN]; // Clients nonce I have signed
                        Encryption::base64Decode(parts[2], nonce, BLELN_TEST_NONCE_LEN);
                        authStore.signData(nonce, BLELN_TEST_NONCE_LEN, friendsNonceSign);
                        sendChallengeNonceSign(cx, friendsNonceSign);
                        cx->setState(BLELNConnCtx::State::ChallengeResponseSer);
                    } else {
                        printk("[E] BLELNServer - ChallengeResponseCli - invalid sign\n");
                        disconnectClient(cx, BT_HCI_ERR_AUTH_FAIL);
                        cx->setState(BLELNConnCtx::State::AuthFailed);
                    }
                } else {
                    printk("[E] BLELNServer - ChallengeResponseCli - wrong message\n");
                    disconnectClient(cx, BT_HCI_ERR_AUTH_FAIL);
                    cx->setState(BLELNConnCtx::State::AuthFailed);
                }
            }
        } else if (cx->getState() == BLELNConnCtx::State::ChallengeResponseSer) {
            std::string plainKeyMsg;
            if (cx->getSessionEnc()->decryptMessage(data, dataLen, plainKeyMsg)) {
                StringList parts = splitCsvRespectingQuotes(plainKeyMsg);
                if (parts[0] == BLELN_MSG_TITLE_AUTH_OK and parts.size() == 2) {
                    printk("[I] BLELNServer - client %d authorised\r\n", cx->getHandle());
                    cx->setState(BLELNConnCtx::State::Authorised);
                }
            }
        }
    }
}

void BLELNServer::worker_processDataRx(uint16_t h, uint8_t *data, size_t dataLen) {
    // If new data message in queue
    BLELNConnCtx *cx;
    // Find context for client who sent data message
    if (getConnContext(h, &cx) and (cx != nullptr)) {
        if (cx->getState() == BLELNConnCtx::State::Authorised) {
            std::string v(reinterpret_cast<char *>(data), dataLen);

            std::string plain;
            if (cx->getSessionEnc()->decryptMessage((const uint8_t *) v.data(), v.size(), plain)) {
                if (plain.size() > 200) plain.resize(200);
                for (auto &ch: plain) if (ch == '\0') ch = ' ';

                if (onMsgReceived)
                    onMsgReceived(cx->getHandle(), plain);
            } else {
                printk("[E] BLELNServer - failed to decrypt data message\n");
            }
        } else {
            disconnectClient(cx, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
        }
    }
}


void BLELNServer::worker_cleanup() {
    auto *action = static_cast<BLELNWorkerAction *>(k_fifo_get(&rx_fifo, K_MSEC(10)));
    while(action){
        k_free(action->d);
        k_free(action);
        action = static_cast<BLELNWorkerAction *>(k_fifo_get(&rx_fifo, K_MSEC(10)));
    }
}


void BLELNServer::sendKeyToClient(BLELNConnCtx *cx) {
    // KEYEX_TX: [ver=1][epoch:4B][salt:32B][srvPub:65B][srvNonce:12B]
    std::string keyex;
    keyex.push_back(1);
    keyex.append((const char*)&g_epoch, 4); // LE
    keyex.append((const char*)g_psk_salt, 32);
    keyex.append((const char*)cx->getSessionEnc()->getMyPub(),65);
    keyex.append((const char*)cx->getSessionEnc()->getMyNonce(),12);

    struct bt_conn *conn= bt_hci_conn_lookup_handle(cx->getHandle());
    bt_gatt_notify_uuid(conn,
                        (struct bt_uuid*)&BLELNBase::KEYEX_TX_UUID,
                        ln_svc.attrs, keyex.data(), keyex.length());
    cx->setState(BLELNConnCtx::State::WaitingForKey);

}

void BLELNServer::sendCertToClient(BLELNConnCtx *cx) {
    std::string msg=BLELN_MSG_TITLE_CERT;
    msg.append(",").append(authStore.getSignedCert());

    std::string encMsg;
    if(cx->getSessionEnc()->encryptMessage(msg, encMsg)) {
        struct bt_conn *conn= bt_hci_conn_lookup_handle(cx->getHandle());
        bt_gatt_notify_uuid(conn,
                            (struct bt_uuid*)&BLELNBase::KEYEX_TX_UUID,
                            ln_svc.attrs, encMsg.data(), encMsg.length());
    } else {
        printk("[E] BLELNServer - BLELNServer - failed encrypting cert msg\n");
    }
}

void BLELNServer::sendChallengeNonce(BLELNConnCtx *cx) {
    cx->generateTestNonce();
    std::string base64Nonce= cx->getTestNonceBase64();

    std::string msg= BLELN_MSG_TITLE_CHALLENGE_RESPONSE_NONCE;
    msg.append(",").append(base64Nonce);

    std::string encMsg;
    if(cx->getSessionEnc()->encryptMessage(msg, encMsg)) {
        struct bt_conn *conn= bt_hci_conn_lookup_handle(cx->getHandle());
        bt_gatt_notify_uuid(conn,
                            (struct bt_uuid*)&BLELNBase::KEYEX_TX_UUID,
                            ln_svc.attrs, encMsg.data(), encMsg.length());
    } else {
        printk("[E] BLELNServer - failed encrypting cert msg\n");
    }
}

void BLELNServer::sendChallengeNonceSign(BLELNConnCtx *cx, uint8_t *sign) {
    std::string msg= BLELN_MSG_TITLE_CHALLENGE_RESPONSE_ANSW;
    std::string base64Sign= Encryption::base64Encode(sign, BLELN_NONCE_SIGN_LEN);
    msg.append(",").append(base64Sign);

    std::string encMsg;
    if(cx->getSessionEnc()->encryptMessage(msg, encMsg)) {
        struct bt_conn *conn= bt_hci_conn_lookup_handle(cx->getHandle());
        bt_gatt_notify_uuid(conn,
                            (struct bt_uuid*)&BLELNBase::KEYEX_TX_UUID,
                            ln_svc.attrs, encMsg.data(), encMsg.length());
    } else {
        printk("[E] BLELNServer - failed encrypting cert msg\n");
    }
}

void BLELNServer::disconnectClient(BLELNConnCtx *cx, uint8_t reason){
    struct bt_conn *conn= bt_hci_conn_lookup_handle(cx->getHandle());
    bt_conn_disconnect(conn, reason);
}

void BLELNServer::appendToDataQueue(uint16_t h, const void *buf, uint16_t len) {
    auto* heapBuf = (uint8_t*)k_malloc(len);
    if (!heapBuf) return;
    memcpy(heapBuf, buf, len);

    auto* pkt= (BLELNWorkerAction*) k_malloc(sizeof(BLELNWorkerAction));
    if (!pkt) { k_free(heapBuf); return; }
    pkt->connH= h;
    pkt->type= BLELN_WORKER_ACTION_PROCESS_DATA_RX;
    pkt->dlen= len;
    pkt->d= heapBuf;

    k_fifo_put(&instance->rx_fifo, pkt);
}

void BLELNServer::appendToKeyQueue(uint16_t h, const void *buf, uint16_t len) {
    auto* heapBuf = (uint8_t*)k_malloc(len);
    if (!heapBuf) return;
    memcpy(heapBuf, buf, len);

    auto* pkt= (BLELNWorkerAction*) k_malloc(sizeof(BLELNWorkerAction));
    if (!pkt) { k_free(heapBuf); return; }
    pkt->connH= h;
    pkt->type= BLELN_WORKER_ACTION_PROCESS_KEY_RX;
    pkt->dlen= len;
    pkt->d= heapBuf;

    k_fifo_put(&instance->rx_fifo, pkt);
}

ssize_t BLELNServer::onDataWrite(struct bt_conn *conn, [[maybe_unused]] const struct bt_gatt_attr *attr,
                                 const void *buf, uint16_t len, uint16_t offset, [[maybe_unused]] uint8_t flags) {
    uint16_t connHandle;
    bt_hci_get_conn_handle(conn, &connHandle);

    if (len==0) {
        return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
    }

    if (offset != 0) {
        return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
    }

    instance->appendToDataQueue(connHandle, buf, len);
    return len;
}

ssize_t BLELNServer::onKeyExRxWrite(struct bt_conn *conn, [[maybe_unused]] const struct bt_gatt_attr *attr,
                                    const void *buf, uint16_t len, uint16_t offset, uint8_t flags) {
    uint16_t connHandle;
    bt_hci_get_conn_handle(conn, &connHandle);

    if (len==0) {
        return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
    }

    if (offset != 0) {
        return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
    }

    instance->appendToKeyQueue(connHandle, buf, len);
    return len;
}

void BLELNServer::onKeyExTxSubscribe(const struct bt_gatt_attr *attr, uint16_t value) {
    bool enabled = (value == BT_GATT_CCC_NOTIFY);

    if(enabled) {
        auto* pkt= (BLELNWorkerAction*) k_malloc(sizeof(BLELNWorkerAction));
        pkt->connH= 0;
        pkt->type= BLELN_WORKER_ACTION_PROCESS_SUBSCRIPTION;
        pkt->dlen= 0;
        pkt->d= nullptr;

        k_fifo_put(&instance->rx_fifo, pkt);
    } else {
        printk("[D] BLELNServer - Client unsubscribed for KeyTX\n");
    }
}

void BLELNServer::stop() {
    if (!instance) return;

    printk("[I] BLELNServer - Stopping...\n");

    instance->runWorker = false;
    bt_le_adv_stop();
    std::vector<struct bt_conn*> connsToDisconnect;

    k_mutex_lock(&instance->clisMtx, K_FOREVER);
    for(auto &ctx : instance->connCtxs) {
        struct bt_conn *conn = bt_hci_conn_lookup_handle(ctx.getHandle());
        if(conn) {
            connsToDisconnect.push_back(conn);
        }
    }
    k_mutex_unlock(&instance->clisMtx);

    for(auto *conn : connsToDisconnect) {
        bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
        bt_conn_unref(conn);
    }

    auto* pkt = (BLELNWorkerAction*) k_malloc(sizeof(BLELNWorkerAction));
    if (pkt) {
        pkt->connH = 0;
        pkt->type = 0xFF;
        pkt->dlen = 0;
        pkt->d = nullptr;
        k_fifo_put(&instance->rx_fifo, pkt);
    }

    k_thread_join(&instance->rx_thread, K_MSEC(1000));

    void* pending;
    while ((pending = k_fifo_get(&instance->rx_fifo, K_NO_WAIT)) != nullptr) {
        auto* action = static_cast<BLELNWorkerAction*>(pending);
        if(action->d) k_free(action->d);
        k_free(action);
    }

    instance->connCtxs.clear();
}


void BLELNServer::connected_cb(struct bt_conn *conn, uint8_t err) {
    uint16_t h;
    bt_hci_get_conn_handle(conn, &h);

    if (!instance || !instance->runWorker) {
        return;
    }

    auto* pkt= (BLELNWorkerAction*) k_calloc(1, sizeof(BLELNWorkerAction));
    if(pkt) {
        pkt->connH= h;
        pkt->type= BLELN_WORKER_ACTION_REGISTER_CONNECTION;
        pkt->dlen= 0;
        pkt->d= nullptr;
        k_fifo_put(&instance->rx_fifo, pkt);
    }

    bt_le_adv_stop();
}

void BLELNServer::disconnected_cb(struct bt_conn *conn, uint8_t reason) {
    uint16_t h;
    bt_hci_get_conn_handle(conn, &h);

    if (!instance || !instance->runWorker) {
        return;
    }

    auto* pkt= (BLELNWorkerAction*) k_malloc(sizeof(BLELNWorkerAction));
    if(pkt) {
        pkt->connH = h;
        pkt->type = BLELN_WORKER_ACTION_DELETE_CONNECTION;
        pkt->dlen = 0;
        pkt->d = nullptr;
        k_fifo_put(&instance->rx_fifo, pkt);
    }

    startAdvertising(instance->advName.c_str());
}

