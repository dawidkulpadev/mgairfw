//
// Created by dkulpa on 17.08.2025.
//

#ifndef MGLIGHTFW_G2_BLELNCONNCTX_H
#define MGLIGHTFW_G2_BLELNCONNCTX_H

#include <zephyr/kernel.h>
#include "BLELNEncryptData.h"

class BLELNConnCtx {
public:
    explicit BLELNConnCtx(uint16_t h);
    ~BLELNConnCtx();

    uint16_t getHandle() const;
    bool isSessionReady() const;
    void setSessionReady(bool ready);

    bool isSendKeyNeeded() const;
    void setKeySent(bool s);

    BLELNEncryptData *getEncData();
private:
    uint16_t handle = 0;
    bool sessionReady = false;
    bool sessionKeySent = false;

    BLELNEncryptData encData;
};


#endif //MGLIGHTFW_G2_BLELNCONNCTX_H
