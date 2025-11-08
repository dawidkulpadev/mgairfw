#include "BLELNClient.h"
#include <cstring>

K_THREAD_STACK_DEFINE(g_rx_stack, 3072);


// --- statyczne wskaźniki do instancji (1 klient na aplikację)
static BLELNClient* g_client_singleton = nullptr;

// --- Auth callbacks (passkey)
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
    const bt_uuid_128* uuid; // oczekujemy LE (LSB-first) tak jak w Zephyr
};

extern "C" bool adv_parse_uuid128_cb(struct bt_data* data, void* user_data) {
    auto* c = static_cast<AdvMatchCtx*>(user_data);
    if (!c || !c->has || !c->uuid) return true;

    // Szukamy tylko pól z 128-bit UUID
    if (data->type != BT_DATA_UUID128_ALL && data->type != BT_DATA_UUID128_SOME) {
        return true;
    }

    // Bardzo defensywnie: nic poza buforem
    const uint8_t* p = static_cast<const uint8_t*>(data->data);
    size_t len = data->data_len;
    while (len >= 16) {
        // porównujemy dokładnie 16 bajtów
        if (memcmp(p, c->uuid->val, 16) == 0) {
            *(c->has) = true;
            return false; // przerwij parse (nie trzeba dalej)
        }
        p += 16;
        len -= 16;
    }
    return true; // kontynuuj z kolejnymi AD strukturami
}

// ===== Utils =====
bool BLELNClient::parse_uuid128(const std::string& s, bt_uuid_128* out) {
    // akceptujemy format XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
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
    // Zephyr używa LE w polu uuid_128.val (LSB-first)
    // Wejściowy string jest MSB-first, więc odwróć:
    for (int i=0;i<16;i++) out->val[i] = bytes[15 - i];
    out->uuid.type = BT_UUID_TYPE_128;
    return true;
}

BLELNClient* BLELNClient::self_from_conn(struct bt_conn* c) {
    return g_client_singleton;
}

// ===== Start/Stop =====
void BLELNClient::start(const std::string& name, std::function<void(const std::string&)> onServerResponse) {
    g_client_singleton = this;

    // BT on
    int err = bt_enable(nullptr);
    if (err) {
        printk("bt_enable err=%d\r\n", err);
        return;
    }

    err = settings_load();   // WAŻNE!
    printk("settings_load -> %d\n", err);


    bt_conn_cb_register(&s_conn_cb);
    bt_conn_auth_cb_register(&s_auth_cb);

    bt_le_oob oob; (void)oob;
    bt_set_name(name.c_str());

    // RX fifo/thread
    k_fifo_init(&rx_fifo);
    runRxWorker = true;
    rxWorkerPaused= true;
    k_thread_create(&rx_thread, g_rx_stack, K_THREAD_STACK_SIZEOF(g_rx_stack),
                    [](void* p1, void*, void*) {
                        static_cast<BLELNClient*>(p1)->rxWorker();
                    },
                    this, nullptr, nullptr, K_PRIO_COOP(8), 0, K_NO_WAIT);

    onMsgRx = std::move(onServerResponse);
}

void BLELNClient::stop() {
    // zatrzymaj scan
    if (scanning) {
        bt_le_scan_stop();
        scanning = false;
    }

    // wyłącz subskrypcje
    if (conn && sub_keyex.value_handle) {
        bt_gatt_unsubscribe(conn, &sub_keyex);
    }
    if (conn && sub_data.value_handle) {
        bt_gatt_unsubscribe(conn, &sub_data);
    }

    // zamknij połączenie
    if (conn) {
        bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
        bt_conn_unref(conn);
        conn = nullptr;
    }

    // rx thread stop
    runRxWorker = false;
    // wrzuć pusty element by obudzić wątek
    k_fifo_put(&rx_fifo, nullptr);

    have_handles = false;
    h_keyex_tx = h_keyex_rx = h_data_tx = h_data_rx = 0;
    s_sid = 0; s_ctr_s2c = s_ctr_c2s = 0;
    memset(s_sessKey_s2c, 0, sizeof(s_sessKey_s2c));
    memset(s_sessKey_c2s, 0, sizeof(s_sessKey_c2s));
    memset(s_cliPub, 0, sizeof(s_cliPub));
    memset(s_srvPub, 0, sizeof(s_srvPub));
    memset(s_cliNonce, 0, sizeof(s_cliNonce));
    memset(s_srvNonce, 0, sizeof(s_srvNonce));
    memset(s_salt, 0, sizeof(s_salt));
    s_epoch = 0;
    g_keyexPayload.clear();
    g_keyexReady = false;

    onMsgRx = nullptr;
    onScanResult = nullptr;
    onConRes = nullptr;
}

// ===== Scan =====
void BLELNClient::startServerSearch(uint32_t durationMs,
                                    const std::string& serverUUID,
                                    const std::function<void(const bt_addr_le_t* addr)>& onResult) {
    onScanResult = onResult;
    scanning = true;

    static const struct bt_le_scan_param params = {
            .type       = BT_LE_SCAN_TYPE_ACTIVE,
            .options    = BT_LE_SCAN_OPT_NONE,
            .interval   = 0x0060, // 60 * 0.625ms = 37.5ms
            .window     = 0x0030, // 30 * 0.625ms = 18.75ms
    };

    int err = bt_le_scan_start(&params, BLELNClient::device_found_cb_new);
    if (err) {
        printk("scan start err=%d\r\n", err);
        scanning = false;
        if (onScanResult) onScanResult(nullptr);
        return;
    }

    // prosty timeout
    k_work_delayable timeout_work;
    k_work_init_delayable(&timeout_work, [](k_work* w){});
    // zamiast k_work tu: prosta zwłoka i stop
    k_sleep(K_MSEC(durationMs));
    if (scanning) {
        bt_le_scan_stop();
        scanning = false;
        if (onScanResult) onScanResult(nullptr);
    }
}

void
BLELNClient::device_found_cb_new(const bt_addr_le_t *addr, int8_t rssi, uint8_t adv_type, struct net_buf_simple *buf) {
    if(g_client_singleton)
        g_client_singleton->handle_adv(addr, buf);
}

void BLELNClient::handle_adv(const bt_addr_le_t *addr, struct net_buf_simple *ad) {
    // sprawdź czy reklama zawiera nasz service UUID (128-bit)
    bool has_service = false;
    bt_data_parse(ad, [](struct bt_data *data, void *user_data){
        auto ctx = static_cast<std::pair<bool*, bt_uuid_128*>*>(user_data);
        if (data->type == BT_DATA_UUID128_ALL || data->type == BT_DATA_UUID128_SOME) {
            // porównaj z uuid_service (LE)
            for (size_t off=0; off + 16 <= data->data_len; off += 16) {
                if (memcmp(data->data + off, ctx->second->val, 16) == 0) {
                    *ctx->first = true;
                    break;
                }
            }
        }
        return true;
    }, (void*)new std::pair<bool*, bt_uuid_128*>{ &has_service, (bt_uuid_128*)&BLELNBase::SERVICE_UUID});

    if (has_service) {
        bt_le_scan_stop();
        scanning = false;
        if (onScanResult) onScanResult(addr);
    }
}

// ===== Connect / Disconnect callbacks =====
void BLELNClient::beginConnect(const bt_addr_le_t* addr, const std::function<void(bool, int)>& onConnectResult) {
    onConRes = onConnectResult;

    bt_conn_le_create_param create_param = {
            .options = BT_CONN_LE_OPT_NONE,
            .interval = BT_GAP_INIT_CONN_INT_MIN,
            .window   = BT_GAP_SCAN_FAST_WINDOW,
            .interval_coded = 0,
            .window_coded   = 0,
            .timeout = 0,
    };
    bt_le_conn_param conn_param = {
            .interval_min = 24, .interval_max = 40, .latency = 0, .timeout = 400
    };

    int err = bt_conn_le_create(addr, &create_param, &conn_param, &conn);
    if (err) {
        if (onConRes) onConRes(false, err);
        return;
    }
    // reszta pójdzie w connected_cb
}

void BLELNClient::connected_cb(struct bt_conn *c, uint8_t err) {
    auto* self = self_from_conn(c);
    if (!self) return;
    if (err) {
        if (self->onConRes) self->onConRes(false, err);
        return;
    }
    // trzymamy referencję
    if (!self->conn) {
        self->conn = bt_conn_ref(c);
    }
    if (self->onConRes) self->onConRes(true, 0);
}

void BLELNClient::disconnected_cb(struct bt_conn *c, uint8_t reason) {
    auto* self = self_from_conn(c);
    if (!self) return;
    (void)reason;
    // posprzątaj lekko (pełny cleanup w stop()/disconnect())
}

void BLELNClient::auth_passkey_entry(struct bt_conn *conn) {
    // wstrzykuj stały passkey 123456, jak w Twojej wersji
    bt_conn_auth_passkey_entry(conn, 123456);
}
void BLELNClient::auth_cancel(struct bt_conn *conn) {
    (void)conn;
}

// ===== Discovery =====
uint8_t BLELNClient::discover_func(struct bt_conn *c, const struct bt_gatt_attr *attr, struct bt_gatt_discover_params *params) {
    auto* self = g_client_singleton;
    if (!self) return BT_GATT_ITER_STOP;
    if (!attr) {
        // koniec
        self->disc_params.func = nullptr;
        return BT_GATT_ITER_STOP;
    }

    const struct bt_gatt_chrc *chrc;
    const struct bt_gatt_service_val *sval;
    switch (params->type) {
        case BT_GATT_DISCOVER_PRIMARY:
            // przejdź do characteristic
            sval = (const bt_gatt_service_val*)attr->user_data;
            if(bt_uuid_cmp((bt_uuid*)sval->uuid, &BLELNBase::SERVICE_UUID.uuid)==0) {
                self->disc_params.uuid = nullptr;
                self->disc_params.type = BT_GATT_DISCOVER_CHARACTERISTIC;
                self->disc_params.start_handle = attr->handle;
                self->disc_params.end_handle = sval->end_handle;
                bt_gatt_discover(c, &self->disc_params);
                return BT_GATT_ITER_STOP;
            } else {
                return BT_GATT_ITER_CONTINUE;
            }

        case BT_GATT_DISCOVER_CHARACTERISTIC:
            chrc = (const bt_gatt_chrc*)attr->user_data;
            char buf2[50];
            bt_uuid_to_str((bt_uuid*)chrc->uuid, buf2, 40);
            if (bt_uuid_cmp(((bt_uuid*)chrc->uuid), &BLELNBase::KEYEX_TX_UUID.uuid) == 0) {
                self->h_keyex_tx = chrc->value_handle;
            } else if (bt_uuid_cmp(((bt_uuid*)chrc->uuid), &BLELNBase::KEYEX_RX_UUID.uuid) == 0) {
                self->h_keyex_rx = chrc->value_handle;
            } else if (bt_uuid_cmp(((bt_uuid*)chrc->uuid), &BLELNBase::DATA_TX_UUID.uuid) == 0) {
                self->h_data_tx = chrc->value_handle;
            } else if (bt_uuid_cmp(((bt_uuid*)chrc->uuid), &BLELNBase::DATA_RX_UUID.uuid) == 0) {
                self->h_data_rx = chrc->value_handle;
            }
            return BT_GATT_ITER_CONTINUE;

        default:
            return BT_GATT_ITER_CONTINUE;
    }
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

    // 1) znajdź usługę
    memset(&disc_params, 0, sizeof(disc_params));
    disc_params.uuid = &BLELNBase::SERVICE_UUID.uuid;
    disc_params.func = discover_func;
    disc_params.type = BT_GATT_DISCOVER_PRIMARY;
    disc_params.start_handle = 0x0001;
    disc_params.end_handle = 0xffff;

    int err = bt_gatt_discover(conn, &disc_params);
    if (err) {
        printk("discover err=%d\r\n", err);
        return false;
    }

    // proste czekanie aż uchwyty się zapełnią (do 2s)
    int tries = 200;
    while (tries-- && (!h_keyex_tx || !h_keyex_rx || !h_data_tx || !h_data_rx )) {
        k_sleep(K_MSEC(10));
    }
    have_handles = h_keyex_tx && h_keyex_rx && h_data_tx && h_data_rx ;
    if (!have_handles){
        printk("discover: -2\r\n");
        return false;
    }

    // 2) Subskrypcje (notify)
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

    return true;
}

// ===== Notifications =====
uint8_t BLELNClient::notify_keyex_cb(struct bt_conn *c,
                                     struct bt_gatt_subscribe_params *params,
                                     const void *data, uint16_t length) {
    auto* self = g_client_singleton;
    if (!self) return BT_GATT_ITER_CONTINUE;
    if (!data || length == 0) return BT_GATT_ITER_CONTINUE;
    self->onKeyExNotify((const uint8_t*)data, length);
    return BT_GATT_ITER_CONTINUE;
}

uint8_t BLELNClient::notify_data_cb(struct bt_conn *c,
                                    struct bt_gatt_subscribe_params *params,
                                    const void *data, uint16_t length) {
    auto* self = g_client_singleton;
    if (!self) return BT_GATT_ITER_CONTINUE;
    if (!data || length == 0) return BT_GATT_ITER_CONTINUE;
    self->onServerResponseNotify((const uint8_t*)data, length);
    return BT_GATT_ITER_CONTINUE;
}

void BLELNClient::onKeyExNotify(const uint8_t* pData, size_t length) {
    g_keyexPayload.assign((const char*)pData, length);
    g_keyexReady = true;
}

void BLELNClient::onServerResponseNotify(const uint8_t* pData, size_t length) {
    if (!pData || !length) return;
    appendToQueue(pData, length);
}

// ===== Handshake (1:1 z Twoją logiką) =====
bool BLELNClient::handshake() {
    // Czekaj max 5s na KEYEX_TX notify
    int64_t t0 = k_uptime_get();
    while (!g_keyexReady && (k_uptime_get() - t0) < 5000) {
        k_sleep(K_MSEC(10));
    }
    if (!g_keyexReady) {
        disconnect();
        printk("[HX] timeout waiting KEYEX_TX notify\r\n");
        return false;
    }

    const std::string& v = g_keyexPayload;
    if (v.size() != 1+4+32+65+12 || (uint8_t)v[0] != 1) {
        printk("[HX] bad keyex len=%u\r\n", (unsigned)v.size());
        return false;
    }
    memcpy(&s_epoch,   &v[1], 4);
    memcpy(s_salt,     &v[1+4], 32);
    memcpy(s_srvPub,   &v[1+4+32], 65);
    memcpy(s_srvNonce, &v[1+4+32+65], 12);

    mbedtls_ecp_group g; mbedtls_mpi d; mbedtls_ecp_point Q;
    if (!BLELNBase::ecdh_gen(s_cliPub, g, d, Q)) {
        printk("[HX] ecdh_gen fail\r\n");
        return false;
    }
    BLELNBase::random_bytes(s_cliNonce, 12);

    // TX do KeyEx RX: [ver=1][cliPub:65][cliNonce:12]
    std::string tx; tx.push_back(1);
    tx.append((const char*)s_cliPub,65);
    tx.append((const char*)s_cliNonce,12);

    int err = bt_gatt_write_without_response(conn, h_keyex_rx, tx.data(), tx.size(), false);
    if (err) {
        printk("[HX] write fail err=%d\r\n", err);
        mbedtls_ecp_point_free(&Q); mbedtls_mpi_free(&d); mbedtls_ecp_group_free(&g);
        return false;
    }

    // ECDH shared
    uint8_t ss[32];
    if (!BLELNBase::ecdh_shared(g, d, s_srvPub, ss)) {
        printk("[HX] shared fail\r\n");
        mbedtls_ecp_point_free(&Q); mbedtls_mpi_free(&d); mbedtls_ecp_group_free(&g);
        return false;
    }

    // HKDF salt = salt || epoch(LE)
    uint8_t salt[36];
    memcpy(salt, s_salt, 32);
    salt[32] = (uint8_t)(s_epoch & 0xFF);
    salt[33] = (uint8_t)((s_epoch >> 8) & 0xFF);
    salt[34] = (uint8_t)((s_epoch >> 16) & 0xFF);
    salt[35] = (uint8_t)((s_epoch >> 24) & 0xFF);

    const char infoHdr_s2c[] = "BLEv1|sessKey_s2c";
    uint8_t info_s2c[sizeof(infoHdr_s2c)-1 + 65 + 65 + 12 + 12], *p_s2c = info_s2c;
    memcpy(p_s2c, infoHdr_s2c, sizeof(infoHdr_s2c)-1); p_s2c += sizeof(infoHdr_s2c)-1;
    memcpy(p_s2c, s_srvPub, 65); p_s2c += 65;
    memcpy(p_s2c, s_cliPub, 65); p_s2c += 65;
    memcpy(p_s2c, s_srvNonce, 12); p_s2c += 12;
    memcpy(p_s2c, s_cliNonce, 12); p_s2c += 12;
    BLELNBase::hkdf_sha256(salt, sizeof(salt), ss, sizeof(ss), info_s2c, (size_t)(p_s2c - info_s2c), s_sessKey_s2c, 32);

    const char infoHdr_c2s[] = "BLEv1|sessKey_c2s";
    uint8_t info_c2s[sizeof(infoHdr_c2s)-1 + 65 + 65 + 12 + 12], *p_c2s = info_c2s;
    memcpy(p_c2s, infoHdr_c2s, sizeof(infoHdr_c2s)-1); p_c2s += sizeof(infoHdr_c2s)-1;
    memcpy(p_c2s, s_srvPub, 65); p_c2s += 65;
    memcpy(p_c2s, s_cliPub, 65); p_c2s += 65;
    memcpy(p_c2s, s_srvNonce, 12); p_c2s += 12;
    memcpy(p_c2s, s_cliNonce, 12); p_c2s += 12;
    BLELNBase::hkdf_sha256(salt, sizeof(salt), ss, sizeof(ss), info_c2s, (size_t)(p_c2s - info_c2s), s_sessKey_c2s, 32);

    uint8_t sidBuf[2];
    const char sidInfo[] = "BLEv1|sid";
    BLELNBase::hkdf_sha256(salt, sizeof(salt), ss, sizeof(ss),
                           (const uint8_t*)sidInfo, sizeof(sidInfo)-1,
                           sidBuf, sizeof(sidBuf));
    s_sid = ((uint16_t)sidBuf[0] << 8) | sidBuf[1];

    s_ctr_s2c = 0;
    s_ctr_c2s = 0;

    mbedtls_ecp_point_free(&Q); mbedtls_mpi_free(&d); mbedtls_ecp_group_free(&g);
    rxWorkerPaused= false;
    return true;
}

// ===== Encrypt & send =====
bool BLELNClient::sendEncrypted(const std::string& msg) {
    if (!conn || !have_handles || s_sid == 0) return false;

    const char aadhdr[] = "DATAv1";
    uint8_t aad[sizeof(aadhdr)-1 + 2 + 4], *a = aad;
    memcpy(a, aadhdr, sizeof(aadhdr)-1); a += sizeof(aadhdr)-1;
    *a++ = (uint8_t)(s_sid >> 8);
    *a++ = (uint8_t)(s_sid & 0xFF);
    *a++ = (uint8_t)(s_epoch & 0xFF);
    *a++ = (uint8_t)((s_epoch >> 8) & 0xFF);
    *a++ = (uint8_t)((s_epoch >> 16) & 0xFF);
    *a   = (uint8_t)((s_epoch >> 24) & 0xFF);

    s_ctr_c2s++;
    uint8_t nonce[12];
    BLELNBase::random_bytes(nonce, 12);
    std::string ct; uint8_t tag[16];

    if (!BLELNBase::gcm_encrypt(s_sessKey_c2s, (const uint8_t*)msg.data(), msg.size(),
                                nonce, aad, sizeof(aad), ct, tag)) {
        printk("[GCM] fail\r\n");
        return false;
    }

    std::string pkt;
    pkt.resize(4);
    pkt[0] = (uint8_t)((s_ctr_c2s >> 24) & 0xFF);
    pkt[1] = (uint8_t)((s_ctr_c2s >> 16) & 0xFF);
    pkt[2] = (uint8_t)((s_ctr_c2s >> 8) & 0xFF);
    pkt[3] = (uint8_t)(s_ctr_c2s & 0xFF);
    pkt.append((const char*)nonce, 12);
    pkt.append(ct);
    pkt.append((const char*)tag, 16);

    // write without response
    int err = bt_gatt_write_without_response(conn, h_data_rx, pkt.data(), pkt.size(), false);
    return (err == 0);
}

// ===== RX Queue / worker =====
void BLELNClient::appendToQueue(const uint8_t* pData, size_t length) {
    auto* heapBuf = (uint8_t*)k_malloc(length);
    if (!heapBuf) return;
    memcpy(heapBuf, pData, length);
    auto* pkt = (RxClientPacket*)k_malloc(sizeof(RxClientPacket));
    if (!pkt) { k_free(heapBuf); return; }
    pkt->len = length;
    pkt->buf = heapBuf;
    k_fifo_put(&rx_fifo, pkt);
}

void BLELNClient::rxWorker() {
    while (runRxWorker) {
        if(!rxWorkerPaused) {
            auto *node = static_cast<RxClientPacket *>(k_fifo_get(&rx_fifo, K_MSEC(50)));
            if (!node) continue;

            if (s_sid != 0) {
                if (node->len >= 4 + 12 + 16) {
                    const uint8_t *ctrBE = node->buf;
                    const uint8_t *nonce = node->buf + 4;
                    const uint8_t *ct = node->buf + 4 + 12;
                    size_t ctLen = node->len - (4 + 12 + 16);
                    const uint8_t *tag = node->buf + (node->len - 16);

                    uint32_t ctr = ((uint32_t) ctrBE[0] << 24) | ((uint32_t) ctrBE[1] << 16) |
                                   ((uint32_t) ctrBE[2] << 8) | ((uint32_t) ctrBE[3]);

                    if (ctr > s_ctr_s2c) {
                        const char aadhdr[] = "DATAv1";
                        uint8_t aad[sizeof(aadhdr) - 1 + 2 + 4], *a = aad;
                        memcpy(a, aadhdr, sizeof(aadhdr) - 1);
                        a += sizeof(aadhdr) - 1;
                        *a++ = (uint8_t) (s_sid >> 8);
                        *a++ = (uint8_t) (s_sid & 0xFF);
                        *a++ = (uint8_t) (s_epoch & 0xFF);
                        *a++ = (uint8_t) ((s_epoch >> 8) & 0xFF);
                        *a++ = (uint8_t) ((s_epoch >> 16) & 0xFF);
                        *a = (uint8_t) ((s_epoch >> 24) & 0xFF);

                        psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
                        psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
                        psa_set_key_bits(&attr, 256);
                        psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
                        psa_set_key_algorithm(&attr, PSA_ALG_GCM);

                        psa_key_id_t key_id = 0;
                        psa_status_t st = psa_import_key(&attr, s_sessKey_s2c, 32, &key_id);
                        if (st == PSA_SUCCESS) {
                            // PSA oczekuje ct||tag w jednym buforze
                            std::string ct_tag;
                            ct_tag.assign((const char *) ct, ctLen);
                            ct_tag.append((const char *) tag, 16);

                            std::string plain;
                            plain.resize(ctLen);
                            size_t plain_len = 0;

                            st = psa_aead_decrypt(key_id, PSA_ALG_GCM,
                                                  nonce, 12,
                                                  aad, sizeof(aad),
                                                  reinterpret_cast<const uint8_t *>(ct_tag.data()), ct_tag.size(),
                                                  reinterpret_cast<uint8_t *>(plain.data()), plain.size(),
                                                  &plain_len);

                            psa_destroy_key(key_id);

                            if (st == PSA_SUCCESS) {
                                plain.resize(plain_len);
                                s_ctr_s2c = ctr;
                                if (onMsgRx) onMsgRx(plain);
                            }
                        }
                    }
                }
            }

            k_free(node->buf);
            k_free(node);
        } else {
            k_sleep(K_MSEC(100));
        }
    }
}

// ===== Disconnect (manual) =====
void BLELNClient::disconnect() {
    if (conn && sub_keyex.value_handle) bt_gatt_unsubscribe(conn, &sub_keyex);
    if (conn && sub_data.value_handle)  bt_gatt_unsubscribe(conn, &sub_data);

    have_handles = false;
    h_keyex_tx = h_keyex_rx = h_data_tx = h_data_rx = 0;

    if (conn) {
        bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
        bt_conn_unref(conn);
        conn = nullptr;
    }

    s_sid = 0;
    s_ctr_s2c = 0;
    s_ctr_c2s = 0;
    memset(s_sessKey_s2c, 0, sizeof(s_sessKey_s2c));
    memset(s_sessKey_c2s, 0, sizeof(s_sessKey_c2s));
    memset(s_cliPub, 0, sizeof(s_cliPub));
    memset(s_srvPub, 0, sizeof(s_srvPub));
    memset(s_cliNonce, 0, sizeof(s_cliNonce));
    memset(s_srvNonce, 0, sizeof(s_srvNonce));
    memset(s_salt, 0, sizeof(s_salt));
    s_epoch = 0;
    g_keyexPayload.clear();
    g_keyexReady = false;
}

bool BLELNClient::parseAdData(struct bt_data *data, void *user_data) {
    return false;
}


