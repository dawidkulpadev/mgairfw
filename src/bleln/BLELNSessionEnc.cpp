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

#include "BLELNSessionEnc.h"
#include "Encryption.h"

bool BLELNSessionEnc::makeMyKeys() {
    if(!Encryption::ecdh_gen(myPub,grp,d)){
        return false;
    }
    Encryption::random_bytes(myNonce,12);

    return true;
}

bool BLELNSessionEnc::deriveFriendsKey(const uint8_t *friendsPub65,
                                       const uint8_t *friendsNonce12, uint8_t *psk_salt, uint32_t sessionEpoch) {
    // ECDH -> shared
    uint8_t ss[32];
    if(!Encryption::ecdh_shared(grp, d, friendsPub65, ss)){
        return false;
    }

    // HKDF: salt = PSK_SALT || epoch (LE)
    uint8_t salt[32+4];
    memcpy(salt, psk_salt, 32);
    salt[32] = (uint8_t)(sessionEpoch & 0xFF);
    salt[33] = (uint8_t)((sessionEpoch >> 8) & 0xFF);
    salt[34] = (uint8_t)((sessionEpoch >> 16) & 0xFF);
    salt[35] = (uint8_t)((sessionEpoch >> 24) & 0xFF);

    // info = "BLEv1|sess" + srvPub + cliPub + srvNonce + cliNonce
    const char infoHdr_f2m[] = "BLEv1|sessKey";
    uint8_t info_f2m[ sizeof(infoHdr_f2m)-1 + 65 + 65 + 12 + 12 ];
    uint8_t* p_f2m = info_f2m;
    memcpy(p_f2m, infoHdr_f2m, sizeof(infoHdr_f2m)-1);  p_f2m += sizeof(infoHdr_f2m)-1;
    memcpy(p_f2m, myPub, 65);                           p_f2m += 65;
    memcpy(p_f2m, friendsPub65, 65);                    p_f2m += 65;
    memcpy(p_f2m, myNonce, 12);                         p_f2m += 12;
    memcpy(p_f2m, friendsNonce12, 12);                  p_f2m += 12;
    auto infoLen_f2m = (size_t)(p_f2m - info_f2m);
    Encryption::hkdf_sha256(salt, sizeof(salt), ss, sizeof(ss), info_f2m, infoLen_f2m,
                            sessKey_f2m, 32);

    // info = "BLEv1|sess" + srvPub + cliPub + srvNonce + cliNonce
    const char infoHdr_m2f[] = "BLEv1|sessKey";
    uint8_t info_m2f[sizeof(infoHdr_m2f) - 1 + 65 + 65 + 12 + 12 ];
    uint8_t* p_m2f = info_m2f;
    memcpy(p_m2f, infoHdr_m2f, sizeof(infoHdr_m2f) - 1); p_m2f += sizeof(infoHdr_m2f) - 1;
    memcpy(p_m2f, friendsPub65, 65); p_m2f += 65;
    memcpy(p_m2f, myPub, 65); p_m2f += 65;
    memcpy(p_m2f, friendsNonce12, 12); p_m2f += 12;
    memcpy(p_m2f, myNonce, 12); p_m2f += 12;
    auto infoLen_m2f = (size_t)(p_m2f - info_m2f);
    Encryption::hkdf_sha256(salt, sizeof(salt), ss, sizeof(ss), info_m2f, infoLen_m2f,
                            sessKey_m2f, 32);

    uint8_t sidBuf[2];
    const char sidInfo[] = "BLEv1|sid";
    Encryption::hkdf_sha256(salt, sizeof(salt),
                            ss, sizeof(ss),
                            (const uint8_t*)sidInfo, sizeof(sidInfo)-1,
                            sidBuf, sizeof(sidBuf));
    sid = ((uint16_t)sidBuf[0] << 8) | sidBuf[1];

    myLastCtr = 0;
    friendsLastCtr = 0;
    myEpoch = sessionEpoch;

    return true;
}

bool BLELNSessionEnc::decryptMessage(const uint8_t *in, size_t inLen, std::string &out) {
    if (inLen < 4 + 12 + 16) {
        return false;
    }

    const uint8_t* p = in;
    uint32_t r_ctr = (p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3]; // Received CTR
    p += 4;
    const uint8_t* iv = p;
    p += 12;
    size_t ctLen = inLen - (4 + 12 + 16);
    const uint8_t* ct = p;
    p += ctLen;
    const uint8_t* tag = p;

    if (r_ctr <= friendsLastCtr){
        return false;
    }

    // AAD = "DATAv1" + handle(LE) + epochUsed(LE)
    const char aadhdr[] = "DATAv1";
    uint8_t aad[ sizeof(aadhdr)-1 + 2 + 4 ];
    uint8_t* a = aad;
    memcpy(a, aadhdr, sizeof(aadhdr)-1); a += sizeof(aadhdr)-1;
    *a++ = (uint8_t)(sid >> 8);
    *a++ = (uint8_t)(sid & 0xFF);
    *a++ = (uint8_t)(myEpoch & 0xFF);
    *a++ = (uint8_t)((myEpoch >> 8) & 0xFF);
    *a++ = (uint8_t)((myEpoch >> 16) & 0xFF);
    *a = (uint8_t)((myEpoch >> 24) & 0xFF);

    if(!Encryption::decryptAESGCM(ct, ctLen, iv, tag, aad, &out, sessKey_f2m)){
        return false;
    }

    friendsLastCtr = r_ctr;
    return true;
}

bool BLELNSessionEnc::encryptMessage(const std::string &in, std::string &out) {
    // AAD = "DATAv1" | sid(BE) | epoch(LE)
    const char aadhdr[] = "DATAv1";
    uint8_t aad[sizeof(aadhdr)-1 + 2 + 4], *a=aad;
    memcpy(a,aadhdr,sizeof(aadhdr)-1);
    a+=sizeof(aadhdr)-1;
    *a++ = (uint8_t)(sid >> 8);
    *a++ = (uint8_t)(sid & 0xFF);
    *a++ = (uint8_t)(myEpoch & 0xFF);
    *a++ = (uint8_t)((myEpoch >> 8) & 0xFF);
    *a++ = (uint8_t)((myEpoch >> 16) & 0xFF);
    *a   = (uint8_t)((myEpoch >> 24) & 0xFF);



    myLastCtr++;
    uint8_t ctrBE[4] = {
            (uint8_t)((myLastCtr>>24)&0xFF), (uint8_t)((myLastCtr>>16)&0xFF),
            (uint8_t)((myLastCtr>>8)&0xFF),  (uint8_t)( myLastCtr&0xFF)
    };
    uint8_t iv[12];
    Encryption::random_bytes(iv, 12);

    std::string ct;
    ct.resize(in.length());
    uint8_t tag[16];



    if(!Encryption::encryptAESGCM(&in, iv, tag, aad, &ct, sessKey_m2f)){
        return false;
    }
    // Pakiet: [ctr:4][nonce:12][cipher...][tag:16]
    out.erase();
    out.append((char*)ctrBE,4);
    out.append((char*)iv,12);
    out.append(ct);
    out.append((char*)tag,16);

    return true;
}

uint8_t *BLELNSessionEnc::getMyPub() {
    return myPub;
}

uint8_t *BLELNSessionEnc::getMyNonce() {
    return myNonce;
}

uint16_t BLELNSessionEnc::getSessionId() const {
    return sid;
}
