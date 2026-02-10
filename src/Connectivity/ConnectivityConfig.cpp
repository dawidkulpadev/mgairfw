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

ConnectivityConfig::ConnectivityConfig(BLELNCert *myCert) {
    BLELNServer::init();
    state= ConfigModeState::Start;
    cert= myCert;

    // Read mac address
    bt_addr_le_t buf;
    size_t count = 1;
    bt_id_get(&buf, &count);
    memcpy(mac, buf.a.val, 6);
}


void ConnectivityConfig::loop() {
    if(state==ConfigModeState::Start){
        printk("Connectivity (Config): Start\r\n");

        BLELNServer::start(BLE_NAME, BLELN_CONFIG_UUID, cert);
        BLELNServer::setOnMessageReceivedCallback([this](uint16_t cliH, const std::string &msg){
            StringList parts= splitCsvRespectingQuotes(msg);
            if(parts[0]=="$CONFIG"){
                char resp[256];

                if(parts[1]=="GET"){
                    if(parts[2]=="wssid"){
                        sprintf(resp, "$CONFIG,VAL,wssid,");
                    } else if(parts[2]=="pcklk"){
                        /*if(this->config->getPicklock()!= nullptr)
                            sprintf(resp, "$CONFIG,VAL,pcklk,%s",this->config->getPicklock());
                        else
                            sprintf(resp, "$CONFIG,VAL,pcklk,");*/
                        sprintf(resp, "$CONFIG,VAL,pcklk,");
                    } else if(parts[2]=="tzone"){
                        sprintf(resp, "$CONFIG,VAL,tzone,");
                    } else if(parts[2]=="mac"){
                        char str_mac[14];
                        uint8_t *macc= this->getMAC();
                        sprintf(str_mac, "%02X%02X%02X%02X%02X%02X", macc[0], macc[1], macc[2], macc[3], macc[4], macc[5]);
                        sprintf(resp, "$CONFIG,VAL,mac,%s", str_mac);
                    }
                } else if(parts[1]=="SET"){
                    if(parts[2]=="pcklk"){
                        sprintf(resp,"$CONFIG,SETOK,pcklk");
                        //this->config->setPicklock(parts[3].c_str());
                    } else if(parts[2]=="uid"){
                        sprintf(resp,"$CONFIG,SETOK,uid");
                        //this->config->setUid(parts[3].c_str());
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
                sys_reboot(SYS_REBOOT_COLD);
            }
        }
    }
}

uint8_t *ConnectivityConfig::getMAC() {
    return mac;
}