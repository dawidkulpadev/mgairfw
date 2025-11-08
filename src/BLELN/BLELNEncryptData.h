//
// Created by dkulpa on 19.08.2025.
//

#ifndef MGLIGHTFW_G2_BLELNENCRYPTDATA_H
#define MGLIGHTFW_G2_BLELNENCRYPTDATA_H

#include <mbedtls/ecp.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <string>

class BLELNEncryptData {
public:
    ~BLELNEncryptData();

    bool makeServerKeys(mbedtls_ctr_drbg_context *ctr_drbg); // Initialize with new server keys
    bool deriveSessionKey(mbedtls_ctr_drbg_context *ctr_drbg, const uint8_t* clientPub65,
                            const uint8_t* clientNonce12, uint8_t *g_psk_salt, uint32_t g_epoch);
    bool decryptAESGCM(const uint8_t* in, size_t inLen, std::string &out);
    bool encryptAESGCM(const std::string &in, std::string &out);

    std::string getPublicKeyString();
    std::string getNonceString();

private:
    mbedtls_ecp_group grp{};
    mbedtls_mpi d{};             // klucz prywatny serwera
    mbedtls_ecp_point Q{};       // publiczny serwera
    uint8_t pub[512]{};          // uncompressed (0x04 + X(32) + Y(32))
    size_t pubLen = 0;

    uint16_t sid = 0;

    uint8_t nonce[12]{};         // nonce serwera dla KeyEx
    uint8_t sessKey_c2s[32]{};          // AES-256-GCM key
    uint8_t sessKey_s2c[32]{};          // AES-256-GCM key
    uint32_t lastCtr_c2s = 0;         // anty-replay
    uint32_t lastCtr_s2c = 0;
    uint32_t epoch = 0;
};


#endif //MGLIGHTFW_G2_BLELNENCRYPTDATA_H
