//
// Created by dkulpa on 19.08.2025.
//


#include <mbedtls/error.h>
#include "BLELNEncryptData.h"
#include "BLELNBase.h"

bool BLELNEncryptData::makeServerKeys(mbedtls_ctr_drbg_context *ctr_drbg) {
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);
    int rc = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (rc != 0) return false;
    rc = mbedtls_ecp_gen_keypair(&grp, &d, &Q,
                                 mbedtls_ctr_drbg_random, ctr_drbg);
    if (rc != 0) return false;
    size_t olen = 0;

    rc = mbedtls_ecp_point_write_binary(&grp, &Q,
                                        MBEDTLS_ECP_PF_UNCOMPRESSED,
                                        &olen, pub, 65);
    if (rc != 0 || olen != 65 || pub[0] != 0x04) return false;
    pubLen = olen;
    BLELNBase::random_bytes(nonce, sizeof(nonce));
    return true;
}

bool BLELNEncryptData::deriveSessionKey(mbedtls_ctr_drbg_context *ctr_drbg, const uint8_t *clientPub65, const uint8_t *clientNonce12, uint8_t *g_psk_salt,
                                        uint32_t g_epoch) {
    // wczytaj punkt klienta
    mbedtls_ecp_point Pcli;
    mbedtls_ecp_point_init(&Pcli);
    int rc = mbedtls_ecp_point_read_binary(&grp, &Pcli, clientPub65, 65);
    if (rc != 0) {
        mbedtls_ecp_point_free(&Pcli);
        return false;
    }

    // shared = ECDH(d_serwera, P_klienta)
    mbedtls_mpi shared;
    mbedtls_mpi_init(&shared);

    rc = mbedtls_ecdh_compute_shared(&grp, &shared, &Pcli, &d,
                                     mbedtls_ctr_drbg_random, ctr_drbg);
    mbedtls_ecp_point_free(&Pcli);
    if (rc != 0) {
        mbedtls_mpi_free(&shared);
        return false;
    }

    uint8_t ss[32]; // P-256 -> 32 bajty
    rc = mbedtls_mpi_write_binary(&shared, ss, sizeof(ss));
    mbedtls_mpi_free(&shared);
    if (rc != 0){
        return false;
    }

    // HKDF: salt = PSK_SALT || epoch (LE)
    uint8_t salt[32+4];
    memcpy(salt, g_psk_salt, 32);
    salt[32] = (uint8_t)(g_epoch & 0xFF);
    salt[33] = (uint8_t)((g_epoch >> 8) & 0xFF);
    salt[34] = (uint8_t)((g_epoch >> 16) & 0xFF);
    salt[35] = (uint8_t)((g_epoch >> 24) & 0xFF);

    // info = "BLEv1|sess" + srvPub + cliPub + srvNonce + cliNonce
    const char infoHdr_c2s[] = "BLEv1|sessKey_c2s";
    uint8_t info_c2s[ sizeof(infoHdr_c2s)-1 + 65 + 65 + 12 + 12 ];
    uint8_t* p_c2s = info_c2s;
    memcpy(p_c2s, infoHdr_c2s, sizeof(infoHdr_c2s)-1); p_c2s += sizeof(infoHdr_c2s)-1;
    memcpy(p_c2s, pub, 65); p_c2s += 65;
    memcpy(p_c2s, clientPub65, 65); p_c2s += 65;
    memcpy(p_c2s, nonce, 12); p_c2s += 12;
    memcpy(p_c2s, clientNonce12, 12); p_c2s += 12;
    auto infoLen_c2s = (size_t)(p_c2s - info_c2s);
    BLELNBase::hkdf_sha256(salt, sizeof(salt), ss, sizeof(ss), info_c2s, infoLen_c2s,
                sessKey_c2s, 32);

    // info = "BLEv1|sess" + srvPub + cliPub + srvNonce + cliNonce
    const char infoHdr_s2c[] = "BLEv1|sessKey_s2c";
    uint8_t info_s2c[sizeof(infoHdr_s2c) - 1 + 65 + 65 + 12 + 12 ];
    uint8_t* p_s2c = info_s2c;
    memcpy(p_s2c, infoHdr_s2c, sizeof(infoHdr_s2c) - 1); p_s2c += sizeof(infoHdr_s2c) - 1;
    memcpy(p_s2c, pub, 65); p_s2c += 65;
    memcpy(p_s2c, clientPub65, 65); p_s2c += 65;
    memcpy(p_s2c, nonce, 12); p_s2c += 12;
    memcpy(p_s2c, clientNonce12, 12); p_s2c += 12;
    auto infoLen_s2c = (size_t)(p_s2c - info_s2c);
    BLELNBase::hkdf_sha256(salt, sizeof(salt), ss, sizeof(ss), info_s2c, infoLen_s2c,
                           sessKey_s2c, 32);

    uint8_t sidBuf[2];
    const char sidInfo[] = "BLEv1|sid";
    BLELNBase::hkdf_sha256(salt, sizeof(salt),
                ss, sizeof(ss),
                (const uint8_t*)sidInfo, sizeof(sidInfo)-1,
                sidBuf, sizeof(sidBuf));
    sid = ((uint16_t)sidBuf[0] << 8) | sidBuf[1];


    lastCtr_s2c = 0;
    lastCtr_s2c = 0;
    epoch = g_epoch;

    return true;
}

bool BLELNEncryptData::decryptAESGCM(const uint8_t* in, size_t inLen, std::string &out) {
    if (inLen < 4 + 12 + 16) {
        return false;
    }

    const uint8_t* p = in;
    uint32_t ctr = (p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3];
    p += 4;
    const uint8_t* iv = p;
    p += 12;
    size_t ctLen = inLen - (4 + 12 + 16);
    const uint8_t* ct = p;
    p += ctLen;
    const uint8_t* tag = p;

    if (ctr <= lastCtr_c2s){
        return false;
    }

    // AAD = "DATAv1" + handle(LE) + epochUsed(LE)
    const char aadhdr[] = "DATAv1";
    uint8_t aad[ sizeof(aadhdr)-1 + 2 + 4 ];
    uint8_t* a = aad;
    memcpy(a, aadhdr, sizeof(aadhdr)-1); a += sizeof(aadhdr)-1;
    *a++ = (uint8_t)(sid >> 8);
    *a++ = (uint8_t)(sid & 0xFF);
    *a++ = (uint8_t)(epoch & 0xFF);
    *a++ = (uint8_t)((epoch >> 8) & 0xFF);
    *a++ = (uint8_t)((epoch >> 16) & 0xFF);
    *a = (uint8_t)((epoch >> 24) & 0xFF);


    mbedtls_gcm_context gcm; mbedtls_gcm_init(&gcm);
    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, sessKey_c2s, 256) != 0) {
        mbedtls_gcm_free(&gcm);
        return false;
    }

    out.resize(ctLen);
    int rc = mbedtls_gcm_auth_decrypt(&gcm, ctLen,
                                      iv, 12,
                                      aad, sizeof(aad),
                                      tag, 16,
                                      ct, (unsigned char*)out.data());
    mbedtls_gcm_free(&gcm);
    if (rc != 0) {
        return false;
    }

    lastCtr_c2s=ctr;
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
    // AAD = "DATAv1" | sid(BE) | epoch(LE)
    const char aadhdr[] = "DATAv1";
    uint8_t aad[sizeof(aadhdr)-1 + 2 + 4], *a=aad;
    memcpy(a,aadhdr,sizeof(aadhdr)-1); a+=sizeof(aadhdr)-1;
    *a++ = (uint8_t)(sid >> 8);
    *a++ = (uint8_t)(sid & 0xFF);
    *a++ = (uint8_t)(epoch & 0xFF);
    *a++ = (uint8_t)((epoch >> 8) & 0xFF);
    *a++ = (uint8_t)((epoch >> 16) & 0xFF);
    *a   = (uint8_t)((epoch >> 24) & 0xFF);

    lastCtr_s2c++;
    uint8_t ctrBE[4] = {
            (uint8_t)((lastCtr_s2c>>24)&0xFF), (uint8_t)((lastCtr_s2c>>16)&0xFF),
            (uint8_t)((lastCtr_s2c>>8)&0xFF),  (uint8_t)( lastCtr_s2c     &0xFF)
    };
    uint8_t iv[12];
    esp_fill_random(iv, sizeof(iv));

    // AES-256-GCM
    mbedtls_gcm_context g; mbedtls_gcm_init(&g);
    if (mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, sessKey_s2c, 256) != 0) { mbedtls_gcm_free(&g); return false; }

    std::string ct;
    ct.resize(in.length());
    uint8_t tag[16];
    if (mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, in.length(),
                                  iv, 12, aad, sizeof(aad),
                                  reinterpret_cast<const unsigned char *>(in.c_str()), (uint8_t*)ct.data(), 16, tag) != 0) {
        mbedtls_gcm_free(&g); return false;
    }
    mbedtls_gcm_free(&g);

    // Pakiet: [ctr:4][nonce:12][cipher...][tag:16]
    out.erase();
    out.append((char*)ctrBE,4);
    out.append((char*)iv,12);
    out.append(ct);
    out.append((char*)tag,16);

    return true;
}

