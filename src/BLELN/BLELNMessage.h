//
// Created by dkulpa on 19.08.2025.
//

#ifndef MGLIGHTFW_G2_BLELNMESSAGE_H
#define MGLIGHTFW_G2_BLELNMESSAGE_H

#include "zephyr/kernel.h"
#include "BLELNConnCtx.h"

class BLELNMessage {
private:
    uint16_t h;
    std::string decrypted;
};


#endif //MGLIGHTFW_G2_BLELNMESSAGE_H
