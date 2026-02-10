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

#ifndef MGAIRFW_ENCRYPTION_H
#define MGAIRFW_ENCRYPTION_H

#include <string>
#include <cstdio>
#include <vector>

#include <mbedtls/gcm.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/base64.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>

class Encryption{
public:
    static void randomizer_init();
    static void random_bytes(uint8_t* out, size_t len);

    static void hkdf_sha256(const uint8_t* salt, size_t salt_len,
                            const uint8_t* ikm, size_t ikm_len,
                            const uint8_t* info, size_t info_len,
                            uint8_t* okm, size_t okm_len);

    static bool ecdh_gen(uint8_t *pub65, mbedtls_ecp_group &g, mbedtls_mpi &d);
    static bool ecdh_shared(const mbedtls_ecp_group &g, const mbedtls_mpi &d, const uint8_t *pub65, uint8_t *out);

    static std::string base64Encode(uint8_t *data, size_t dlen);
    static size_t base64Decode(const std::string &in, uint8_t *out, size_t outLen);

    static bool decryptAESGCM(const uint8_t* ct, size_t ctLen, const uint8_t *iv, const uint8_t *tag,
                              uint8_t *aad, std::string *out, uint8_t *key);
    static bool encryptAESGCM(const std::string *in, uint8_t *iv, uint8_t *tag,
                              uint8_t *aad, std::string *out, uint8_t *key);

    static bool signData_ECDSA_P256(const uint8_t* data, size_t dataLen,
                                    const uint8_t* privKeyD, size_t privKeyDLen,
                                    uint8_t* signatureOut, size_t sigOutLen);
    static bool verifySign_ECDSA_P256(const uint8_t* data, size_t dataLen, const uint8_t* signature, size_t sigLen,
                                      const uint8_t* pubKeyRaw, size_t pubKeyLen);

private:
    static bool rngInitialised;
    static mbedtls_entropy_context entropy;
    static mbedtls_ctr_drbg_context ctr_drbg;
};


#endif //MGAIRFW_ENCRYPTION_H
