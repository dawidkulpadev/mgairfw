//
// Created by dkulpa on 9.02.2026.
//

#include "BLELNCert.h"
#include <zephyr/sys/util.h>

BLELNCert::BLELNCert(const std::string& certSignHex, const std::string& manuPubKeyHex,
                     const std::string& myPrivateKeyHex, const std::string& myPublicKeyHex){
    hex2bin(certSignHex.c_str(), certSignHex.size(), certSign, BLELN_MANU_SIGN_LEN);
    hex2bin(manuPubKeyHex.c_str(), manuPubKeyHex.size(), manuPubKey, BLELN_MANU_PUB_KEY_LEN);
    hex2bin(myPrivateKeyHex.c_str(), myPrivateKeyHex.size(), myPrivateKey, BLELN_DEV_PRIV_KEY_LEN);
    hex2bin(myPublicKeyHex.c_str(), myPublicKeyHex.size(), myPublicKey, BLELN_DEV_PUB_KEY_LEN);
}

const uint8_t *BLELNCert::getCertSign() const {
    return certSign;
}

const uint8_t *BLELNCert::getManuPubKey() const {
    return manuPubKey;
}

const uint8_t *BLELNCert::getMyPrivateKey() const {
    return myPrivateKey;
}

const uint8_t *BLELNCert::getMyPublicKey() const {
    return myPublicKey;
}
