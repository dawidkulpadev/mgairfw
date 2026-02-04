// BLELNBase.h — Zephyr (nRF52840)
// 2025-10-18

#ifndef MGLIGHTFW_G2_BLELNBASE_H
#define MGLIGHTFW_G2_BLELNBASE_H

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/random/random.h>
#include <zephyr/settings/settings.h>
#include <zephyr/bluetooth/uuid.h>

#include <mbedtls/gcm.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <psa/crypto.h>

#include <cstdint>
#include <cstddef>
#include <string>
#include <cstring>

void hexDump(const char* label, const uint8_t* data, size_t len);


class BLELNBase {
public:
    static constexpr struct bt_uuid_128 CLIENT_SERVICE_UUID  =
            BT_UUID_INIT_128(BT_UUID_128_ENCODE(0x952cb13b, 0x57fa, 0x4885, 0xa445, 0x57d1f17328fd));
    static constexpr struct bt_uuid_128 CONFIGER_SERVICE_UUID =
            BT_UUID_INIT_128(BT_UUID_128_ENCODE(0xe0611e96, 0xd399, 0x4101, 0x8507 ,0x1f23ee392891));
    static constexpr struct bt_uuid_128 KEYEX_TX_UUID =
            BT_UUID_INIT_128(BT_UUID_128_ENCODE(0xef7cb0fc, 0x53a4, 0x4062, 0xbb0e, 0x25443e3a1f5d));
    static constexpr struct bt_uuid_128 KEYEX_RX_UUID =
            BT_UUID_INIT_128(BT_UUID_128_ENCODE(0x345ac506, 0xc96e, 0x45c6, 0xa418, 0x56a2ef2d6072));
    static constexpr struct bt_uuid_128 DATA_TX_UUID  =
            BT_UUID_INIT_128(BT_UUID_128_ENCODE(0xb675ddff, 0x679e, 0x458d, 0x9960, 0x939d8bb03572));
    static constexpr struct bt_uuid_128 DATA_RX_UUID  =
            BT_UUID_INIT_128(BT_UUID_128_ENCODE(0x566f9eb0, 0xa95e, 0x4c18, 0xbc45, 0x79bd396389af));

    // RNG / DRBG
    static bool rngInitialised;

    // --- HKDF(SHA-256)
    static void hkdf_sha256(const uint8_t* salt, size_t salt_len,
                            const uint8_t* ikm,  size_t ikm_len,
                            const uint8_t* info, size_t info_len,
                            uint8_t* okm,        size_t okm_len);

    static void random_bytes(uint8_t* out, size_t len);

    // --- PSK storage (Zephyr Settings/NVS)
    // przechowujemy klucze pod ścieżką "bleln/salt" i "bleln/epoch"
    static int  settings_init_and_load();
    static void load_or_init_psk(uint8_t* g_psk_salt, uint32_t* g_epoch);
    static void rotate_psk(uint8_t* g_psk_salt, uint32_t* g_epoch);

    // --- ECDH P-256
    static bool ecdh_gen(uint8_t pub65[65], mbedtls_ecp_group& g, mbedtls_mpi& d, mbedtls_ecp_point& Q);
    static bool ecdh_shared(const mbedtls_ecp_group& g, const mbedtls_mpi& d,
                            const uint8_t pub65[65], uint8_t out[32]);

    // --- AES-GCM
    static bool gcm_encrypt(const uint8_t key[32],
                            const uint8_t* plain, size_t plen,
                            const uint8_t* nonce12,
                            const uint8_t* aad, size_t aadLen,
                            std::string& out, uint8_t tag[16]);

private:
    // Cache ładowanych ustawień przez Settings
    static inline uint8_t  s_salt[32];
    static inline uint32_t s_epoch   = 0;
    static inline bool     s_loaded  = false;

    // Settings handler (odbiera "bleln/salt" i "bleln/epoch" podczas settings_load())
    static int settings_set_cb(const char* key, size_t len_rd, settings_read_cb read_cb, void* cb_arg);
    static inline struct settings_handler s_settings_handler {
            .name = "bleln",
            .h_set = BLELNBase::settings_set_cb,
    };
};

#endif // MGLIGHTFW_G2_BLELNBASE_H