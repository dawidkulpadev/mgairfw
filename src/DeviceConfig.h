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

#ifndef UNTITLED_DEVICECONFIG_H
#define UNTITLED_DEVICECONFIG_H

#include "bleln/BLELNBase.h"

#define DEVICECONFIG_NAMESPACE_BASE "base"


#define DEVICECONFIG_NAMESPACE_ID   "id"
#define DEVICECONFIG_KEY_UID        "uid"
#define DEVICECONFIG_KEY_PICKLOCK   "picklock"
#define DEVICECONFIG_KEY_CERTSIGN   "certsign"
#define DEVICECONFIG_KEY_LAST_SERVER_MAC    "lsm"


#define FACTORY_DATA_ADDR 0xFC000

class DeviceConfig {
public:
    static int id_settings_set(const char *name, size_t len,
                               settings_read_cb read_cb, void *cb_arg);
    static int base_settings_set(const char *name, size_t len,
                                 settings_read_cb read_cd, void *cb_arg);

    DeviceConfig();

    // base
    std::string getLastServerMAC();
    void setLastServerMAC(std::string mac);

    // id
    std::string getUid() const;
    std::string getPicklock();
    const uint8_t* getCertSign() const;

    void setUid(std::string v);
    void setPicklock(std::string v);
    void setCertSignFromBase64(const std::string& b64);

    // cert
    const uint8_t* getManuPubKey() const;
    const uint8_t* getMyPrivateKey() const;
    const uint8_t* getMyPublicKey() const;


    static bool registerConfig();
    int processIdConfigRead(const char *name, size_t len,
                            settings_read_cb read_cb, void *cb_arg);
    int processBaseConfigRead(const char *name, size_t len,
                            settings_read_cb read_cb, void *cb_arg);

    void writeIdConfig();


    void loadFactoryData();

    void factoryReset();

private:

    // id
    std::string lastServerMAC;
    std::string uid;
    std::string picklock;
    uint8_t certSign[BLELN_MANU_SIGN_LEN]{};

    // cert
    uint8_t factoryCertSign[BLELN_MANU_SIGN_LEN]{};
    uint8_t manuPubKey[BLELN_MANU_PUB_KEY_LEN]{};
    uint8_t myPrivateKey[BLELN_DEV_PRIV_KEY_LEN]{};
    uint8_t myPublicKey[BLELN_DEV_PUB_KEY_LEN]{};

    bool factoryDataLoaded = false;
};

extern DeviceConfig devicesConfig;


#endif //UNTITLED_DEVICECONFIG_H
