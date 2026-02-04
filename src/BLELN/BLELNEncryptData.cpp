//
// Created by dkulpa on 19.08.2025.
//


#include <mbedtls/error.h>
#include "BLELNEncryptData.h"
#include "BLELNBase.h"

bool BLELNEncryptData::makeServerKeys()
{
    if (!BLELNBase::ecdh_gen(pub, grp, d, Q)) {
        printk("[SX] ecdh_gen failed\r\n");
        return false;
    }

    pubLen = 65;
    BLELNBase::random_bytes(nonce, sizeof(nonce));

    return true;
}

bool BLELNEncryptData::deriveSessionKey(const uint8_t *clientPub65,
                                        const uint8_t *clientNonce12,
                                        const uint8_t *g_psk_salt,
                                        uint32_t g_epoch)
{
    // --- 1. ECDH(shared) = d_serwera ⨉ P_klienta ---
    uint8_t ss[32]; // sekretny shared secret (P-256 → 32 bajty)
    if (!BLELNBase::ecdh_shared(grp, d, clientPub65, ss)) {
        printk("[HX] ecdh_shared failed\r\n");
        return false;
    }

    // --- 2. HKDF salt = PSK_SALT || epoch(LE) ---
    uint8_t salt[32 + 4];
    memcpy(salt, g_psk_salt, 32);
    salt[32] = (uint8_t)(g_epoch & 0xFF);
    salt[33] = (uint8_t)((g_epoch >> 8) & 0xFF);
    salt[34] = (uint8_t)((g_epoch >> 16) & 0xFF);
    salt[35] = (uint8_t)((g_epoch >> 24) & 0xFF);

    // --- 3. HKDF: sessKey_c2s ---
    // info_c2s = "BLEv1|sessKey_c2s" + srvPub + cliPub + srvNonce + cliNonce
    const char infoHdr_c2s[] = "BLEv1|sessKey_c2s";
    uint8_t info_c2s[ sizeof(infoHdr_c2s) - 1 + 65 + 65 + 12 + 12 ];
    uint8_t *p_c2s = info_c2s;

    memcpy(p_c2s, infoHdr_c2s, sizeof(infoHdr_c2s) - 1);
    p_c2s += sizeof(infoHdr_c2s) - 1;
    memcpy(p_c2s, pub, 65);              // srvPub
    p_c2s += 65;
    memcpy(p_c2s, clientPub65, 65);      // cliPub
    p_c2s += 65;
    memcpy(p_c2s, nonce, 12);            // srvNonce
    p_c2s += 12;
    memcpy(p_c2s, clientNonce12, 12);    // cliNonce
    p_c2s += 12;

    size_t infoLen_c2s = (size_t)(p_c2s - info_c2s);

    BLELNBase::hkdf_sha256(
            salt, sizeof(salt),
            ss, sizeof(ss),
            info_c2s, infoLen_c2s,
            sessKey_c2s, 32
    );

    // --- 4. HKDF: sessKey_s2c ---
    // info_s2c = "BLEv1|sessKey_s2c" + srvPub + cliPub + srvNonce + cliNonce
    const char infoHdr_s2c[] = "BLEv1|sessKey_s2c";
    uint8_t info_s2c[ sizeof(infoHdr_s2c) - 1 + 65 + 65 + 12 + 12 ];
    uint8_t *p_s2c = info_s2c;

    memcpy(p_s2c, infoHdr_s2c, sizeof(infoHdr_s2c) - 1);
    p_s2c += sizeof(infoHdr_s2c) - 1;
    memcpy(p_s2c, pub, 65);              // srvPub
    p_s2c += 65;
    memcpy(p_s2c, clientPub65, 65);      // cliPub
    p_s2c += 65;
    memcpy(p_s2c, nonce, 12);            // srvNonce
    p_s2c += 12;
    memcpy(p_s2c, clientNonce12, 12);    // cliNonce
    p_s2c += 12;

    size_t infoLen_s2c = (size_t)(p_s2c - info_s2c);

    BLELNBase::hkdf_sha256(
            salt, sizeof(salt),
            ss, sizeof(ss),
            info_s2c, infoLen_s2c,
            sessKey_s2c, 32
    );

    // --- 5. HKDF: SID ---
    uint8_t sidBuf[2];
    const char sidInfo[] = "BLEv1|sid";

    BLELNBase::hkdf_sha256(
            salt, sizeof(salt),
            ss, sizeof(ss),
            (const uint8_t *)sidInfo, sizeof(sidInfo) - 1,
            sidBuf, sizeof(sidBuf)
    );

    sid = (uint16_t)((sidBuf[0] << 8) | sidBuf[1]);

    // --- 6. Reset liczników i zapamiętanie epoch ---
    lastCtr_s2c = 0;
    lastCtr_c2s = 0;    // tu u Ciebie w oryginale był mały bug: przypisanie do lastCtr_s2c drugi raz :)
    epoch = g_epoch;

    return true;
}

bool BLELNEncryptData::decryptAESGCM(const uint8_t* in, size_t inLen, std::string &out) {
    if (inLen < 4 + 12 + 16) {
        return false;
    }

    const uint8_t *ctrBE = in;
    const uint8_t *iv = in + 4;
    const uint8_t *ct = in + 4 + 12;
    size_t ctLen = inLen - (4 + 12 + 16);
    const uint8_t *tag = in + (inLen - 16);

    uint32_t ctr = ((uint32_t) ctrBE[0] << 24) | ((uint32_t) ctrBE[1] << 16) |
                   ((uint32_t) ctrBE[2] << 8) | ((uint32_t) ctrBE[3]);

    if (ctr > lastCtr_c2s) {
        const char aadhdr[] = "DATAv1";
        uint8_t aad[sizeof(aadhdr) - 1 + 2 + 4];
        uint8_t *a = aad;
        memcpy(a, aadhdr, sizeof(aadhdr) - 1);
        a += sizeof(aadhdr) - 1;
        *a++ = (uint8_t) (sid >> 8);
        *a++ = (uint8_t) (sid & 0xFF);
        *a++ = (uint8_t) (epoch & 0xFF);
        *a++ = (uint8_t) ((epoch >> 8) & 0xFF);
        *a++ = (uint8_t) ((epoch >> 16) & 0xFF);
        *a = (uint8_t) ((epoch >> 24) & 0xFF);

        psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
        psa_set_key_bits(&attr, 256);
        psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
        psa_set_key_algorithm(&attr, PSA_ALG_GCM);

        psa_key_id_t key_id = 0;
        psa_status_t st = psa_import_key(&attr, sessKey_c2s, 32, &key_id);
        if (st == PSA_SUCCESS) {
            // PSA oczekuje ct||tag w jednym buforze
            std::string ct_tag;
            ct_tag.assign((const char *) ct, ctLen);
            ct_tag.append((const char *) tag, 16);

            out.erase();
            out.resize(ctLen);
            size_t plain_len = 0;

            st = psa_aead_decrypt(key_id, PSA_ALG_GCM,
                                  iv, 12,
                                  aad, sizeof(aad),
                                  reinterpret_cast<const uint8_t *>(ct_tag.data()), ct_tag.size(),
                                  reinterpret_cast<uint8_t *>(out.data()), out.size(),
                                  &plain_len);

            psa_destroy_key(key_id);

            if (st == PSA_SUCCESS) {
                out.resize(plain_len);
                lastCtr_c2s= ctr;

            } else {
                return false;
            }
        } else {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

BLELNEncryptData::~BLELNEncryptData() {
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
}

std::string BLELNEncryptData::getPublicKeyString() {
    return {reinterpret_cast<char*>(pub), pubLen};
}

std::string BLELNEncryptData::getNonceString() {
    return {reinterpret_cast<char*>(nonce), sizeof(nonce)};
}

bool BLELNEncryptData::encryptAESGCM(const std::string &in, std::string &out) {
    if (sid == 0) return false;

    const char aadhdr[] = "DATAv1";
    uint8_t aad[sizeof(aadhdr)-1 + 2 + 4], *a = aad;
    memcpy(a, aadhdr, sizeof(aadhdr)-1); a += sizeof(aadhdr)-1;
    *a++ = (uint8_t)(sid >> 8);
    *a++ = (uint8_t)(sid & 0xFF);
    *a++ = (uint8_t)(epoch & 0xFF);
    *a++ = (uint8_t)((epoch >> 8) & 0xFF);
    *a++ = (uint8_t)((epoch >> 16) & 0xFF);
    *a   = (uint8_t)((epoch >> 24) & 0xFF);

    lastCtr_s2c++;
    uint8_t iv[12];
    BLELNBase::random_bytes(iv, 12);
    std::string ct;
    uint8_t tag[16];

    if (!BLELNBase::gcm_encrypt(sessKey_s2c, (const uint8_t*)in.data(), in.size(),
                                iv, aad, sizeof(aad), ct, tag)) {
        printk("[GCM] fail\r\n");
        return false;
    }

    out.erase();
    out.resize(4);
    out[0] = (uint8_t)((lastCtr_s2c >> 24) & 0xFF);
    out[1] = (uint8_t)((lastCtr_s2c >> 16) & 0xFF);
    out[2] = (uint8_t)((lastCtr_s2c >> 8) & 0xFF);
    out[3] = (uint8_t)(lastCtr_s2c & 0xFF);
    out.append((const char*)iv, 12);
    out.append(ct);
    out.append((const char*)tag, 16);

    return true;
}

