//
// Created by dkulpa on 9.02.2026.
//

#ifndef MGAIRFW_BLELNCERT_H
#define MGAIRFW_BLELNCERT_H

#include <zephyr/kernel.h>
#include "BLELNBase.h"

class BLELNCert {
public:
    BLELNCert(const std::string& certSignHex, const std::string& manuPubKeyHex, const std::string& myPrivateKeyHex, const std::string& myPublicKeyHex);

    [[nodiscard]] const uint8_t *getCertSign() const;
    [[nodiscard]] const uint8_t *getManuPubKey() const;
    [[nodiscard]] const uint8_t *getMyPrivateKey() const;
    [[nodiscard]] const uint8_t *getMyPublicKey() const;

private:
    uint8_t certSign[BLELN_MANU_SIGN_LEN];
    uint8_t manuPubKey[BLELN_MANU_PUB_KEY_LEN];
    uint8_t myPrivateKey[BLELN_DEV_PRIV_KEY_LEN];
    uint8_t myPublicKey[BLELN_DEV_PUB_KEY_LEN];
};


#endif //MGAIRFW_BLELNCERT_H
