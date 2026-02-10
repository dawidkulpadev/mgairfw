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

#ifndef MGAIRFW_BLELNSESSIONENC_H
#define MGAIRFW_BLELNSESSIONENC_H

#include <mbedtls/ecp.h>
#include <mbedtls/ctr_drbg.h>
#include "string"

class BLELNSessionEnc {
public:
    bool makeMyKeys(); // Initialize with new server keys
    bool deriveFriendsKey(const uint8_t* friendsPub65, const uint8_t* friendsNonce12, uint8_t *psk_salt, uint32_t sessionEpoch);
    bool decryptMessage(const uint8_t* in, size_t inLen, std::string &out);
    bool encryptMessage(const std::string &in, std::string &out);

    uint16_t getSessionId() const;

    uint8_t* getMyPub();
    uint8_t* getMyNonce();
private:
    // Connection encryption
    uint16_t sid = 0;
    uint32_t myEpoch = 0;

    // My data
    mbedtls_ecp_group grp{};
    mbedtls_mpi d{};             // my private key

    uint8_t sessKey_m2f[32]{};   // AES-256-GCM key
    uint32_t myLastCtr = 0;     // anty-replay
    uint8_t myNonce[12]{};
    uint8_t myPub[65]{};           // my public key

    // Friend data
    uint8_t sessKey_f2m[32]{};   // AES-256-GCM key
    uint32_t friendsLastCtr = 0;    // anty-replay
};



#endif //MGAIRFW_BLELNSESSIONENC_H
