//
// Created by dkulpa on 17.08.2025.
//

#include "BLELNConnCtx.h"

BLELNConnCtx::BLELNConnCtx(uint16_t h) {
    sessionReady = false;
    handle = h;
}

BLELNConnCtx::~BLELNConnCtx() {

}

uint16_t BLELNConnCtx::getHandle() const {
    return handle;
}


void BLELNConnCtx::setSessionReady(bool ready) {
    sessionReady = ready;
}

bool BLELNConnCtx::isSessionReady() const {
    return sessionReady;
}


bool BLELNConnCtx::isSendKeyNeeded() const {
    return !sessionKeySent;
}

void BLELNConnCtx::setKeySent(bool s) {
    sessionKeySent = s;
}

BLELNEncryptData *BLELNConnCtx::getEncData() {
    return &encData;
}


