/**
    MioGiapicco Light Firmware - Firmware for Light Device of MioGiapicco system
    Copyright (C) 2023  Dawid Kulpa

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

#include <zephyr/drivers/flash.h>
#include <algorithm>
#include "DeviceConfig.h"
#include "bleln/Encryption.h"

DeviceConfig devicesConfig;


static struct settings_handler id_conf = {
        .name= DEVICECONFIG_NAMESPACE_ID,
        .h_set= DeviceConfig::id_settings_set
};

static struct settings_handler base_conf = {
        .name= DEVICECONFIG_NAMESPACE_BASE,
        .h_set= DeviceConfig::base_settings_set
};


struct __attribute__((packed)) factory_data_t {
    uint32_t magic;          // 0x4D474B50
    uint8_t  mac[6];
    uint8_t  _pad[2];
    uint8_t  manu_pub[64];
    uint8_t  dev_priv[32];
    uint8_t  dev_pub[64];
    uint8_t  signature[64];
};

DeviceConfig::DeviceConfig() {
    memset(certSign, 0, BLELN_MANU_SIGN_LEN);
    picklock= "";
    uid="-1";
    lastServerMAC="";
}

std::string DeviceConfig::getUid() const {
    return uid;
}

std::string DeviceConfig::getPicklock() {
    return picklock;
}

const uint8_t *DeviceConfig::getCertSign() const {
    return certSign;
}

void DeviceConfig::setUid(std::string v) {
    uid= std::move(v);
}

void DeviceConfig::setPicklock(std::string v) {
    picklock= std::move(v);
}

void DeviceConfig::setCertSignFromBase64(const std::string& b64) {
    Encryption::base64Decode(b64, certSign, BLELN_MANU_SIGN_LEN);
}

const uint8_t *DeviceConfig::getManuPubKey() const {
    return manuPubKey;
}

const uint8_t *DeviceConfig::getMyPrivateKey() const {
    return myPrivateKey;
}

const uint8_t *DeviceConfig::getMyPublicKey() const {
    return myPublicKey;
}

void DeviceConfig::loadFactoryData() {
    if (factoryDataLoaded) return;

    const struct device *flash_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_flash_controller));
    struct factory_data_t data{};

    if (!device_is_ready(flash_dev)) {
        printk("[Factory] Flash device not ready\n");
        return;
    }

    int rc = flash_read(flash_dev, FACTORY_DATA_ADDR, &data, sizeof(data));
    if (rc != 0 || data.magic != 0x4D474B50) {
        printk("[Factory] Invalid data at 0x%X (Magic: 0x%08X)\n", FACTORY_DATA_ADDR, data.magic);
        return;
    }

    // Kopiowanie do buforów klasy
    memcpy(manuPubKey, data.manu_pub, BLELN_MANU_PUB_KEY_LEN);
    memcpy(myPrivateKey, data.dev_priv, BLELN_DEV_PRIV_KEY_LEN);
    memcpy(myPublicKey, data.dev_pub, BLELN_DEV_PUB_KEY_LEN);
    memcpy(factoryCertSign, data.signature, BLELN_MANU_SIGN_LEN);

    bool certIsZero= std::all_of(std::begin(certSign), std::end(certSign), [](int i){
        return i==0;
    });

    if(certIsZero){
        memcpy(certSign, factoryCertSign, BLELN_MANU_SIGN_LEN);
    }

    factoryDataLoaded = true;
    printk("[Factory] Keys loaded successfully from Flash.\n");
}

bool DeviceConfig::registerConfig() {
    settings_register(&id_conf);
    settings_register(&base_conf);

    return true;
}


void DeviceConfig::writeIdConfig() {
    settings_save_one(DEVICECONFIG_NAMESPACE_ID "/" DEVICECONFIG_KEY_UID,
                      uid.c_str(), uid.size()+1);
    settings_save_one(DEVICECONFIG_NAMESPACE_ID "/" DEVICECONFIG_KEY_PICKLOCK,
                      picklock.c_str(), picklock.size()+1);
    settings_save_one(DEVICECONFIG_NAMESPACE_ID "/" DEVICECONFIG_KEY_CERTSIGN,
                      certSign, BLELN_MANU_SIGN_LEN);
}

void DeviceConfig::factoryReset() {
    settings_delete(DEVICECONFIG_NAMESPACE_ID "/" DEVICECONFIG_KEY_UID);
    settings_delete(DEVICECONFIG_NAMESPACE_ID "/" DEVICECONFIG_KEY_PICKLOCK);
    settings_save_one(DEVICECONFIG_NAMESPACE_ID "/" DEVICECONFIG_KEY_CERTSIGN,
                      factoryCertSign, BLELN_MANU_SIGN_LEN);
}

int DeviceConfig::id_settings_set(const char *name, size_t len,
                                  settings_read_cb read_cb, void *cb_arg){
    return devicesConfig.processIdConfigRead(name, len, read_cb, cb_arg);
}

int DeviceConfig::base_settings_set(const char *name, size_t len, settings_read_cb read_cb, void *cb_arg) {
    return devicesConfig.processBaseConfigRead(name, len, read_cb, cb_arg);
}

int DeviceConfig::processIdConfigRead(const char *name, size_t len,
                                      settings_read_cb read_cb, void *cb_arg) {
    const char *next;
    int rc;

    if (settings_name_steq(name, DEVICECONFIG_KEY_UID, &next) && !next) {
        char buf[32];
        rc = read_cb(cb_arg, buf, len);
        printk("userId: %s\n", buf);
        if (rc > 0) {
            uid= buf;
            return 0;
        }

        uid= "-1";
        return rc;
    } else if (settings_name_steq(name, DEVICECONFIG_KEY_PICKLOCK, &next) && !next) {
        char buf[256];
        rc = read_cb(cb_arg, buf, len);
        if (rc > 0) {
            picklock= buf;
            return 0;
        }

        picklock= "";
        return rc;
    } else if (settings_name_steq(name, DEVICECONFIG_KEY_CERTSIGN, &next) && !next) {
        rc = read_cb(cb_arg, certSign, BLELN_MANU_SIGN_LEN);
        if (rc > 0) {
            return 0;
        }

        return rc;
    }


    return -ENOENT;
}

int DeviceConfig::processBaseConfigRead(const char *name, size_t len, settings_read_cb read_cb, void *cb_arg) {
    const char *next;
    int rc;

    if (settings_name_steq(name, DEVICECONFIG_KEY_LAST_SERVER_MAC, &next) && !next) {
        char buf[32];
        rc = read_cb(cb_arg, buf, len);
        if (rc > 0) {
            lastServerMAC= buf;
            return 0;
        }

        lastServerMAC= "";
        return rc;
    }


    return -ENOENT;
}

std::string DeviceConfig::getLastServerMAC() {
    return lastServerMAC;
}

void DeviceConfig::setLastServerMAC(std::string mac) {
    lastServerMAC= std::move(mac);
}




