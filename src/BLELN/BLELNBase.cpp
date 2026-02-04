// BLELNBase.cpp — Zephyr (nRF52840)

#include "BLELNBase.h"

bool BLELNBase::rngInitialised = false;

void hexDump(const char* label, const uint8_t* data, size_t len) {
    printk("%s [%u]: ", label, (unsigned)len);
    for (size_t i = 0; i < len; ++i) {
        printk("%02X", data[i]);
        if (i + 1 < len) printk(" ");
        if (i != 0 && (i % 20) == 0) printk("\r\n");
    }
    printk("\r\n");
}

// proste HMAC-SHA256 na mbedtls_sha256_*
static void hmac_sha256(const uint8_t* key, size_t key_len,
                        const uint8_t* data, size_t data_len,
                        uint8_t out[32]) {
    uint8_t k_ipad[64], k_opad[64], khash[32];

    // Klucz do 64 bajtów (SHA-256 block size)
    uint8_t key_block[64];
    if (key_len > 64) {
        mbedtls_sha256_context ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts(&ctx, 0);
        mbedtls_sha256_update(&ctx, key, key_len);
        mbedtls_sha256_finish(&ctx, key_block);
        mbedtls_sha256_free(&ctx);
        memset(key_block + 32, 0, 32);
    } else {
        memcpy(key_block, key, key_len);
        memset(key_block + key_len, 0, 64 - key_len);
    }

    for (int i = 0; i < 64; ++i) {
        k_ipad[i] = key_block[i] ^ 0x36;
        k_opad[i] = key_block[i] ^ 0x5c;
    }

    // inner = SHA256(k_ipad || data)
    mbedtls_sha256_context ictx;
    mbedtls_sha256_init(&ictx);
    mbedtls_sha256_starts(&ictx, 0);
    mbedtls_sha256_update(&ictx, k_ipad, 64);
    mbedtls_sha256_update(&ictx, data, data_len);
    mbedtls_sha256_finish(&ictx, khash);
    mbedtls_sha256_free(&ictx);

    // outer = SHA256(k_opad || inner)
    mbedtls_sha256_context octx;
    mbedtls_sha256_init(&octx);
    mbedtls_sha256_starts(&octx, 0);
    mbedtls_sha256_update(&octx, k_opad, 64);
    mbedtls_sha256_update(&octx, khash, 32);
    mbedtls_sha256_finish(&octx, out);
    mbedtls_sha256_free(&octx);
}

void BLELNBase::hkdf_sha256(const uint8_t* salt, size_t salt_len,
                            const uint8_t* ikm,  size_t ikm_len,
                            const uint8_t* info, size_t info_len,
                            uint8_t* okm,        size_t okm_len) {
    // Extract: PRK = HMAC(salt, IKM)  (jeśli salt brak → same zera)
    uint8_t zero_salt[32]; memset(zero_salt, 0, sizeof(zero_salt));
    const uint8_t* s = (salt && salt_len) ? salt : zero_salt;
    size_t s_len = (salt && salt_len) ? salt_len : sizeof(zero_salt);

    uint8_t prk[32];
    hmac_sha256(s, s_len, ikm, ikm_len, prk);

    // Expand:
    uint8_t T[32]; size_t Tlen = 0; size_t out_off = 0; uint8_t counter = 1;
    while (out_off < okm_len) {
        // data = T(prev) || info || counter
        uint8_t tmp[32 + 256 + 1]; // 256: wystarczy dla typowego 'info' w Twoim kodzie
        size_t pos = 0;
        if (Tlen) { memcpy(tmp + pos, T, Tlen); pos += Tlen; }
        if (info && info_len) { memcpy(tmp + pos, info, info_len); pos += info_len; }
        tmp[pos++] = counter;

        hmac_sha256(prk, sizeof(prk), tmp, pos, T);

        size_t cpy = MIN((size_t)32, okm_len - out_off);
        memcpy(okm + out_off, T, cpy);
        out_off += cpy;
        Tlen = 32;
        counter++;
    }
}

static int zephyr_rng_cb(void* /*ctx*/, unsigned char* out, size_t len) {
    // sys_csrand_get zwraca 0 przy sukcesie
    return sys_csrand_get(out, len);
}

void BLELNBase::random_bytes(uint8_t* out, size_t len) {
    // Preferuj szybki CSPRNG Zephyra:
    int rc = sys_csrand_get(out, len);
    if (rc == 0) return;
}

// ---------- Settings (NVS) ----------
int BLELNBase::settings_set_cb(const char* key, size_t len_rd, settings_read_cb read_cb, void* cb_arg) {
    if (strcmp(key, "salt") == 0) {
        if (len_rd == sizeof(s_salt)) {
            (void)read_cb(cb_arg, s_salt, sizeof(s_salt));
            s_loaded = true;
        }
        return 0;
    }
    if (strcmp(key, "epoch") == 0) {
        if (len_rd == sizeof(s_epoch)) {
            (void)read_cb(cb_arg, &s_epoch, sizeof(s_epoch));
            s_loaded = true;
        }
        return 0;
    }
    return -ENOENT;
}

int BLELNBase::settings_init_and_load() {
    static bool inited = false;
    if (!inited) {
        int rc = settings_subsys_init();
        if (rc) return rc;

        rc = settings_register(&s_settings_handler);
        if (rc) return rc;

        rc = settings_load();
        if (rc) return rc;

        inited = true;
    }
    return 0;
}

void BLELNBase::load_or_init_psk(uint8_t* g_psk_salt, uint32_t* g_epoch) {
    (void)settings_init_and_load();

    // jeśli nie było w NVS, zainicjalizuj
    if (!s_loaded || s_epoch == 0) {
        random_bytes(s_salt, sizeof(s_salt));
        s_epoch = 1;

        (void)settings_save_one("bleln/salt",  s_salt, sizeof(s_salt));
        (void)settings_save_one("bleln/epoch", &s_epoch, sizeof(s_epoch));
        printk("[PSK] Initialized (epoch=%u)\r\n", s_epoch);
    }

    memcpy(g_psk_salt, s_salt, sizeof(s_salt));
    *g_epoch = s_epoch;
}

void BLELNBase::rotate_psk(uint8_t* g_psk_salt, uint32_t* g_epoch) {
    (void)settings_init_and_load();

    random_bytes(s_salt, sizeof(s_salt));
    s_epoch = (s_epoch == 0) ? 1 : (s_epoch + 1);

    (void)settings_save_one("bleln/salt",  s_salt, sizeof(s_salt));
    (void)settings_save_one("bleln/epoch", &s_epoch, sizeof(s_epoch));

    memcpy(g_psk_salt, s_salt, sizeof(s_salt));
    *g_epoch = s_epoch;

    printk("[PSK] Rotated. New epoch=%u\r\n", s_epoch);
}

// ---------- ECDH P-256 ----------
bool BLELNBase::ecdh_gen(uint8_t pub65[65], mbedtls_ecp_group& g, mbedtls_mpi& d, mbedtls_ecp_point& Q) {
    mbedtls_ecp_group_init(&g);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);

    if (mbedtls_ecp_group_load(&g, MBEDTLS_ECP_DP_SECP256R1) != 0)
        return false;

    if (mbedtls_ecp_gen_keypair(&g, &d, &Q, zephyr_rng_cb, nullptr) != 0)
        return false;

    size_t olen = 0;
    if (mbedtls_ecp_point_write_binary(&g, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pub65, 65) != 0)
        return false;

    return (olen == 65 && pub65[0] == 0x04);
}

bool BLELNBase::ecdh_shared(const mbedtls_ecp_group& g, const mbedtls_mpi& d,
                            const uint8_t pub65[65], uint8_t out[32]) {
    mbedtls_ecp_point P; mbedtls_ecp_point_init(&P);
    if (mbedtls_ecp_point_read_binary(&g, &P, pub65, 65) != 0) {
        mbedtls_ecp_point_free(&P);
        return false;
    }
    mbedtls_mpi sh; mbedtls_mpi_init(&sh);
    if (mbedtls_ecdh_compute_shared((mbedtls_ecp_group*)&g, &sh, &P, (mbedtls_mpi*)&d,
                                    zephyr_rng_cb, nullptr) != 0) {
        mbedtls_ecp_point_free(&P);
        mbedtls_mpi_free(&sh);
        return false;
    }
    bool ok = (mbedtls_mpi_write_binary(&sh, out, 32) == 0);
    mbedtls_ecp_point_free(&P);
    mbedtls_mpi_free(&sh);
    return ok;
}

// ---------- AES-GCM ----------
bool BLELNBase::gcm_encrypt(const uint8_t key[32],
                            const uint8_t* plain, size_t plen,
                            const uint8_t* nonce12,
                            const uint8_t* aad, size_t aadLen,
                            std::string& out, uint8_t tag[16]) {
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);

    psa_key_id_t key_id = 0;
    psa_status_t st = psa_import_key(&attr, key, 32, &key_id);
    if (st != PSA_SUCCESS) return false;

    // PSA zwraca ciphertext||tag w jednym buforze
    size_t out_needed = plen + 16;
    std::string tmp; tmp.resize(out_needed);
    size_t out_len = 0;

    st = psa_aead_encrypt(key_id, PSA_ALG_GCM,
                          nonce12, 12,
                          aad, aadLen,
                          plain, plen,
                          reinterpret_cast<uint8_t*>(tmp.data()), tmp.size(),
                          &out_len);

    psa_destroy_key(key_id);

    if (st != PSA_SUCCESS || out_len < 16) return false;

    // rozdziel na ct i tag (jak w Twoim protokole)
    size_t ct_len = out_len - 16;
    out.assign(tmp.data(), ct_len);
    memcpy(tag, tmp.data() + ct_len, 16);
    return true;
}