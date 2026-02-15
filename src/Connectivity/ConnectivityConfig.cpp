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

#include "ConnectivityConfig.h"
#include "DeviceConfig.h"

ConnectivityConfig::ConnectivityConfig() {
    BLELNServer::init(devicesConfig.getCertSign(), devicesConfig.getManuPubKey(),
                      devicesConfig.getMyPrivateKey(), devicesConfig.getMyPublicKey(),
                      devicesConfig.getUid());
    state= ConfigModeState::Start;

    // Read mac address
    bt_addr_le_t buf;
    size_t count = 1;
    bt_id_get(&buf, &count);
    memcpy(mac, buf.a.val, 6);
}


void ConnectivityConfig::loop() {
    if(state==ConfigModeState::Start){
        printk("Connectivity (Config): Start\r\n");

        BLELNServer::start(BLE_NAME, BLELN_CONFIG_UUID);
        BLELNServer::setOnMessageReceivedCallback([this](uint16_t cliH, const std::string &msg){
            StringList parts= splitCsvRespectingQuotes(msg);
            if(parts[0]=="$CONFIG"){
                char resp[256];

                if(parts[1]=="GET"){
                    if(parts[2]=="wssid"){
                        sprintf(resp, "$CONFIG,VAL,wssid,");
                    } else if(parts[2]=="pcklk"){
                        sprintf(resp, "$CONFIG,VAL,pcklk,");
                    } else if(parts[2]=="tzone"){
                        sprintf(resp, "$CONFIG,VAL,tzone,");
                    } else if(parts[2]=="role"){
                        sprintf(resp, "$CONFIG,VAL,role,0");
                    }
                } else if(parts[1]=="SET"){
                    if(parts[2]=="wssid"){
                        sprintf(resp,"$CONFIG,SETOK,wssid");
                    } else if(parts[2]=="wpsk"){
                        sprintf(resp,"$CONFIG,SETOK,wpsk");
                    } else if(parts[2]=="pcklk"){
                        sprintf(resp,"$CONFIG,SETOK,pcklk");
                        devicesConfig.setPicklock(parts[3]);
                    } else if(parts[2]=="tzone"){
                        sprintf(resp,"$CONFIG,SETOK,tzone");
                    } else if(parts[2]=="uid"){
                        sprintf(resp,"$CONFIG,SETOK,uid");
                        devicesConfig.setUid(parts[3]);
                    } else if(parts[2]=="role"){
                        sprintf(resp,"$CONFIG,SETOK,role");
                    } else if(parts[2]=="certsign"){
                        sprintf(resp,"$CONFIG,SETOK,certsign");
                        devicesConfig.setCertSignFromBase64(parts[3]);
                    }
                }

                if(strlen(resp)>0){
                    BLELNServer::sendEncrypted(cliH, resp);
                }
            } else if(parts[0]=="$REBOOT"){
                rebootCalledAt= k_uptime_get();
                rebootCalled= true;
            }
        });

        state = ConfigModeState::ServerTasking;
    } else if(state==ConfigModeState::ServerTasking){
        if(rebootCalled){
            if(rebootCalledAt + 2000 < k_uptime_get()){
                devicesConfig.writeIdConfig();
                k_sleep(K_MSEC(500));
                sys_reboot(SYS_REBOOT_COLD);
            }
        }
    }
}

uint8_t *ConnectivityConfig::getMAC() {
    return mac;
}