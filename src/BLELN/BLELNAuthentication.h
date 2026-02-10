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

#ifndef MGLIGHTFW_BLELNAUTHENTICATION_H
#define MGLIGHTFW_BLELNAUTHENTICATION_H

#include "mbedtls/base64.h"
#include "BLELNBase.h"
#include <zephyr/settings/settings.h>

#include "BLELNCert.h"

class BLELNAuthentication {
public:
    void loadCert(BLELNCert *myCert);
    std::string getSignedCert();
    bool verifyCert(const std::string &cert, const std::string &sign, uint8_t *genOut, uint8_t *macOut,
                    int macOutLen, uint8_t *pubKeyOut, int pubKeyOutLen);
    void signData(const uint8_t *d, size_t dlen, uint8_t *out);

private:
    uint8_t certSign[BLELN_MANU_SIGN_LEN];
    uint8_t manuPubKey[BLELN_MANU_PUB_KEY_LEN];
    uint8_t myPrivateKey[BLELN_DEV_PRIV_KEY_LEN];
    uint8_t myPublicKey[BLELN_DEV_PUB_KEY_LEN];
};

#endif //MGLIGHTFW_BLELNAUTHENTICATION_H
