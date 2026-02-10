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


#include <stdexcept>
#include <zephyr/bluetooth/addr.h>
#include <zephyr/bluetooth/bluetooth.h>
#include "BLELNAuthentication.h"
#include "Encryption.h"
#include "SuperString.h"
#include <charconv>

void BLELNAuthentication::loadCert(BLELNCert *myCert) {
    memcpy(certSign, myCert->getCertSign(), BLELN_MANU_SIGN_LEN);
    memcpy(manuPubKey, myCert->getManuPubKey(), BLELN_MANU_PUB_KEY_LEN);
    memcpy(myPrivateKey, myCert->getMyPrivateKey() , BLELN_DEV_PRIV_KEY_LEN);
    memcpy(myPublicKey, myCert->getMyPublicKey(), BLELN_DEV_PUB_KEY_LEN);
}

std::string BLELNAuthentication::getSignedCert() {
    // # Cert:
    // product generation - as text
    // ;
    // devices mac 6 bytes  - base64
    // ;
    // devices public key 64 bytes - base64
    // # Sign:
    // ,
    // certSign - base64

    std::string out;
    bt_addr_le_t mac;
    size_t count = 1;
    bt_id_get(&mac, &count);

    out.append("2;");
    out.append(Encryption::base64Encode(mac.a.val, 6));
    out.append(";");
    out.append(Encryption::base64Encode(myPublicKey, BLELN_DEV_PUB_KEY_LEN));
    out.append(",");
    out.append(Encryption::base64Encode(certSign, BLELN_MANU_SIGN_LEN));

    return out;
}


bool BLELNAuthentication::verifyCert(const std::string &cert, const std::string &sign, uint8_t *genOut, uint8_t *macOut,
                                     int macOutLen, uint8_t *pubKeyOut, int pubKeyOutLen) {
    uint8_t signRaw[BLELN_MANU_SIGN_LEN];
    Encryption::base64Decode(sign, signRaw, BLELN_MANU_SIGN_LEN);

    bool r= Encryption::verifySign_ECDSA_P256(reinterpret_cast<const uint8_t *>(cert.data()), cert.length(),
                                              signRaw, BLELN_MANU_SIGN_LEN, manuPubKey, BLELN_MANU_PUB_KEY_LEN);

    if((macOutLen < 6) or (pubKeyOutLen < BLELN_DEV_PUB_KEY_LEN)){
        return false;
    }

    if(r){
        StringList certSplit= splitCsvRespectingQuotes(cert, ';');


        auto [ptr, ec] = std::from_chars(certSplit[0].data(), certSplit[0].data() + certSplit[0].size(), *genOut);
         if (ec == std::errc::invalid_argument or ec == std::errc::result_out_of_range) {
             return false;
        }

        if(Encryption::base64Decode(certSplit[1], macOut, macOutLen)==6){
            if(Encryption::base64Decode(certSplit[2], pubKeyOut, pubKeyOutLen)!=BLELN_DEV_PUB_KEY_LEN){
                return false;
            }
        } else {
            return false;
        }
    }

    return r;
}

void BLELNAuthentication::signData(const uint8_t *d, size_t dlen, uint8_t *out) {
    Encryption::signData_ECDSA_P256(d, dlen,
                                    myPrivateKey, BLELN_DEV_PRIV_KEY_LEN, out, BLELN_DEV_SIGN_LEN);
}

