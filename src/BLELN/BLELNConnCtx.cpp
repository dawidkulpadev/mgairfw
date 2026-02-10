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

#include "BLELNConnCtx.h"

BLELNConnCtx::BLELNConnCtx(uint16_t handle) {
    s= State::New;
    h = handle;
    birthTime= k_uptime_get();
}

BLELNConnCtx::~BLELNConnCtx() {

}

uint16_t BLELNConnCtx::getHandle() const {
    return h;
}

void BLELNConnCtx::setState(BLELNConnCtx::State state) {
    s= state;
}

BLELNConnCtx::State BLELNConnCtx::getState() {
    return s;
}

bool BLELNConnCtx::makeSessionKey() {
    if(s==State::New) {
        if(bse.makeMyKeys()){
            s= State::Initialised;
            return true;
        }
    }

    return false;
}

BLELNSessionEnc *BLELNConnCtx::getSessionEnc() {
    return &bse;
}

void BLELNConnCtx::setCertData(uint8_t *macAddress, uint8_t *publicKey) {
    memcpy(mac6, macAddress, 6);
    memcpy(pubKey64, publicKey, BLELN_DEV_PUB_KEY_LEN);
}

void BLELNConnCtx::generateTestNonce() {
    Encryption::random_bytes(testNonce48, BLELN_TEST_NONCE_LEN);
}


bool BLELNConnCtx::verifyChallengeResponseAnswer(uint8_t *nonceSign) {
    return Encryption::verifySign_ECDSA_P256(testNonce48, BLELN_TEST_NONCE_LEN, nonceSign,
                                             BLELN_DEV_SIGN_LEN, pubKey64, BLELN_DEV_PUB_KEY_LEN);
}

uint8_t *BLELNConnCtx::getTestNonce() {
    return testNonce48;
}

std::string BLELNConnCtx::getTestNonceBase64() {
    return Encryption::base64Encode(testNonce48, BLELN_TEST_NONCE_LEN);
}

uint64_t BLELNConnCtx::getTimeOfLife() const {
    return k_uptime_get()-birthTime;
}


