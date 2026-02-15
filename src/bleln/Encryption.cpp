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

#include "Encryption.h"

bool Encryption::rngInitialised = false;
mbedtls_entropy_context Encryption::entropy;
mbedtls_ctr_drbg_context Encryption::ctr_drbg;

void Encryption::randomizer_init() {
    if (!rngInitialised) {
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);

        // Na nRF52840 z włączonym CryptoCell, domyślne źródło entropii
        // korzysta ze sprzętowego generatora liczb losowych (CC310 TRNG).
        const char *pers = "srv-ecdh-nrf";

        int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                        (const unsigned char *) pers, strlen(pers));

        if (ret == 0) {
            rngInitialised = true;
        } else {
            // Obsługa błędu inicjalizacji RNG
            printf("Encryption - RNG Init Failed: -0x%04X\n", -ret);
        }
    }
}

void Encryption::random_bytes(uint8_t *out, size_t len) {
    randomizer_init();
    // Zamiast esp_fill_random używamy mbedTLS DRBG, który czerpie ze sprzętowego RNG Nordica
    int ret = mbedtls_ctr_drbg_random(&ctr_drbg, out, len);
    if(ret != 0) {
        printf("Encryption - Random Bytes Failed: -0x%04X\n", -ret);
    }
}

void Encryption::hkdf_sha256(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
                             const uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len) {
    // SHA-256 jest wspierane sprzętowo przez CC310, jeśli mbedTLS jest poprawnie skonfigurowany.
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    uint8_t prk[32];
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, md, 1);

    mbedtls_md_hmac_starts(&ctx, salt, salt_len);
    mbedtls_md_hmac_update(&ctx, ikm, ikm_len);
    mbedtls_md_hmac_finish(&ctx, prk);

    uint8_t T[32];
    size_t Tlen = 0, out_off = 0;
    uint8_t cnt = 1;

    // Używamy std::min zamiast min, wymaga <algorithm> lub definicji makra, 
    // tutaj prosta implementacja inline dla kompatybilności.
    auto local_min = [](size_t a, size_t b) { return (a < b) ? a : b; };

    while (out_off < okm_len) {
        mbedtls_md_hmac_starts(&ctx, prk, 32);
        if (Tlen) mbedtls_md_hmac_update(&ctx, T, Tlen);
        mbedtls_md_hmac_update(&ctx, info, info_len);
        mbedtls_md_hmac_update(&ctx, &cnt, 1);
        mbedtls_md_hmac_finish(&ctx, T);

        size_t cpy = local_min((size_t)32, okm_len - out_off);
        memcpy(okm + out_off, T, cpy);
        out_off += cpy;
        Tlen = 32;
        cnt++;
    }
    mbedtls_md_free(&ctx);
    // Zeroizacja klucza tymczasowego dla bezpieczeństwa
    mbedtls_platform_zeroize(prk, sizeof(prk));
}

bool Encryption::ecdh_gen(uint8_t *pub65, mbedtls_ecp_group &g, mbedtls_mpi &d) {
    // CC310 sprzętowo przyspiesza operacje na krzywych (mbedtls_ecp_*)
    mbedtls_ecp_point Q;
    mbedtls_ecp_point_init(&Q);
    mbedtls_ecp_group_init(&g);
    mbedtls_mpi_init(&d);

    if(mbedtls_ecp_group_load(&g, MBEDTLS_ECP_DP_SECP256R1) != 0) {
        mbedtls_ecp_point_free(&Q);
        return false;
    }

    if(mbedtls_ecp_gen_keypair(&g, &d, &Q, mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
        mbedtls_ecp_point_free(&Q);
        return false;
    }

    size_t olen = 0;
    // Zapis klucza publicznego
    if(mbedtls_ecp_point_write_binary(&g, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pub65, 65) != 0) {
        mbedtls_ecp_point_free(&Q);
        return false;
    }

    mbedtls_ecp_point_free(&Q);
    return (olen == 65 && pub65[0] == 0x04);
}

bool Encryption::ecdh_shared(const mbedtls_ecp_group &g, const mbedtls_mpi &d, const uint8_t *pub65, uint8_t *out) {
    mbedtls_ecp_point P;
    mbedtls_ecp_point_init(&P);

    if(mbedtls_ecp_point_read_binary(&g, &P, pub65, 65) != 0){
        mbedtls_ecp_point_free(&P);
        return false;
    }

    mbedtls_mpi sh;
    mbedtls_mpi_init(&sh);

    // Obliczenie współdzielonego sekretu (sprzętowo na nRF52840)
    if(mbedtls_ecdh_compute_shared((mbedtls_ecp_group*)&g, &sh, &P, (mbedtls_mpi*)&d,
                                   mbedtls_ctr_drbg_random, &ctr_drbg) != 0){
        mbedtls_ecp_point_free(&P);
        mbedtls_mpi_free(&sh);
        return false;
    }

    bool ok = (mbedtls_mpi_write_binary(&sh, out, 32) == 0);

    mbedtls_ecp_point_free(&P);
    mbedtls_mpi_free(&sh);
    return ok;
}

bool Encryption::decryptAESGCM(const uint8_t *ct, size_t ctLen, const uint8_t *iv, const uint8_t *tag,
                               uint8_t *aad, std::string *out, uint8_t *key) {
    // CC310 wspiera AES-GCM
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256) != 0) {
        mbedtls_gcm_free(&gcm);
        return false;
    }

    out->resize(ctLen);
    int rc = mbedtls_gcm_auth_decrypt(&gcm, ctLen,
                                      iv, 12,
                                      aad, 12,
                                      tag, 16,
                                      ct, (unsigned char*)out->data());
    mbedtls_gcm_free(&gcm);

    return (rc == 0);
}

bool Encryption::encryptAESGCM(const std::string *in, uint8_t *iv, uint8_t *tag,
                               uint8_t *aad, std::string *out, uint8_t *key) {
    mbedtls_gcm_context g;
    mbedtls_gcm_init(&g);

    if (mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, key, 256) != 0) {
        mbedtls_gcm_free(&g);
        return false;
    }

    // Upewnij się, że buffer wyjściowy ma odpowiedni rozmiar
    out->resize(in->length());

    if (mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, in->length(),
                                  iv, 12, aad, 12,
                                  reinterpret_cast<const unsigned char *>(in->c_str()),
                                  (uint8_t*)out->data(), 16, tag) != 0) {
        mbedtls_gcm_free(&g);
        return false;
    }
    mbedtls_gcm_free(&g);

    return true;
}

bool Encryption::verifySign_ECDSA_P256(const uint8_t* data, size_t dataLen,
                                       const uint8_t* signature, size_t sigLen,
                                       const uint8_t* pubKeyRaw, size_t pubKeyLen){
    constexpr size_t P256_RS_SIG_LEN        = 64;
    constexpr size_t P256_UNCOMP_PUBKEY_LEN = 65;
    constexpr size_t P256_COORD_LEN         = 32;

    int ret = 0;

    if (data == nullptr || dataLen == 0 ||
        signature == nullptr || sigLen != P256_RS_SIG_LEN ||
        pubKeyRaw == nullptr ||
        (pubKeyLen != P256_UNCOMP_PUBKEY_LEN && pubKeyLen != 2 * P256_COORD_LEN)) {
        return false;
    }

    mbedtls_ecp_group group;
    mbedtls_ecp_point Q;
    mbedtls_mpi r, s;
    unsigned char hash[32] = {0};
    // Bufor alokowany na stosie, nie VLA
    unsigned char pubKeyBuf[P256_UNCOMP_PUBKEY_LEN];

    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    // CC310 wspiera SHA-256
    ret = mbedtls_sha256(data, dataLen, hash, 0);
    if (ret != 0) goto cleanup;

    ret = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) goto cleanup;

    if (pubKeyLen == P256_UNCOMP_PUBKEY_LEN) {
        if (pubKeyRaw[0] != 0x04) {
            ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            goto cleanup;
        }
        memcpy(pubKeyBuf, pubKeyRaw, P256_UNCOMP_PUBKEY_LEN);
    } else {
        pubKeyBuf[0] = 0x04;
        memcpy(pubKeyBuf + 1, pubKeyRaw, 2 * P256_COORD_LEN);
    }

    ret = mbedtls_ecp_point_read_binary(&group, &Q, pubKeyBuf, P256_UNCOMP_PUBKEY_LEN);
    if (ret != 0) goto cleanup;

    // Walidacja klucza publicznego (sprzętowa weryfikacja punktu na krzywej)
    ret = mbedtls_ecp_check_pubkey(&group, &Q);
    if (ret != 0) goto cleanup;

    ret = mbedtls_mpi_read_binary(&r, signature, P256_COORD_LEN);
    if (ret != 0) goto cleanup;

    ret = mbedtls_mpi_read_binary(&s, signature + P256_COORD_LEN, P256_COORD_LEN);
    if (ret != 0) goto cleanup;

    // Weryfikacja podpisu ECDSA (sprzętowo)
    ret = mbedtls_ecdsa_verify(&group, hash, sizeof(hash), &Q, &r, &s);

    cleanup:
    mbedtls_platform_zeroize(hash, sizeof(hash));
    mbedtls_ecp_group_free(&group);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return (ret == 0);
}

bool Encryption::signData_ECDSA_P256(const uint8_t* data, size_t dataLen,
                                     const uint8_t* privKeyD, size_t privKeyDLen,
                                     uint8_t* signatureOut, size_t sigOutLen) {
    constexpr size_t P256_D_LEN      = 32;
    constexpr size_t P256_RS_SIG_LEN = 64;

    int ret = 0;

    if (data == nullptr || dataLen == 0 ||
        privKeyD == nullptr || privKeyDLen != P256_D_LEN ||
        signatureOut == nullptr || sigOutLen != P256_RS_SIG_LEN) {
        return false;
    }

    unsigned char hash[32] = {0};

    mbedtls_ecp_group group;
    mbedtls_mpi d, r, s;

    mbedtls_ecp_group_init(&group);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    ret = mbedtls_sha256(data, dataLen, hash, 0);
    if (ret != 0) goto cleanup;

    ret = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) goto cleanup;

    ret = mbedtls_mpi_read_binary(&d, privKeyD, P256_D_LEN);
    if (ret != 0) goto cleanup;

    if (mbedtls_mpi_cmp_int(&d, 0) == 0 || mbedtls_mpi_cmp_mpi(&d, &group.N) >= 0) {
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    // Podpis ECDSA (sprzętowo przyśpieszany)
    // Używamy deterministycznego podpisu lub losowego (tutaj losowy RNG)
    ret = mbedtls_ecdsa_sign(&group, &r, &s, &d, hash, sizeof(hash),
                             mbedtls_ctr_drbg_random, &ctr_drbg);

    if (ret != 0) goto cleanup;

    ret = mbedtls_mpi_write_binary(&r, signatureOut, 32);
    if (ret != 0) goto cleanup;

    ret = mbedtls_mpi_write_binary(&s, signatureOut + 32, 32);
    if (ret != 0) goto cleanup;

    cleanup:
    mbedtls_platform_zeroize(hash, sizeof(hash));
    mbedtls_ecp_group_free(&group);
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return (ret == 0);
}

std::string Encryption::base64Encode(uint8_t *data, size_t dlen) {
    size_t olen = 0;
    // Pierwsze wywołanie, by pobrać rozmiar
    mbedtls_base64_encode(nullptr, 0, &olen, data, dlen);

    // Używamy std::vector zamiast VLA (Variable Length Array), co jest bezpieczniejsze w C++
    std::vector<char> buffer(olen + 1);

    if(mbedtls_base64_encode((unsigned char*)buffer.data(), buffer.size(), &olen, data, dlen) != 0){
        printf("Encryption - base64Encode - failed encoding!\n");
        return "";
    }
    buffer[olen] = 0; // null-terminator

    return std::string(buffer.data());
}

size_t Encryption::base64Decode(const std::string &in, uint8_t *out, size_t outLen) {
    size_t rlen = 0;
    if(mbedtls_base64_decode(out, outLen, &rlen,
                             reinterpret_cast<const unsigned char *>(in.c_str()), in.size()) != 0){
        printf("Encryption - base64Decode - failed decoding!\n");
        return 0;
    }

    return rlen;
}