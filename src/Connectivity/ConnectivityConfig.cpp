//
// Created by dkulpa on 1.10.2025.
//

#include "ConnectivityConfig.h"

ConnectivityConfig::ConnectivityConfig() {
    BLELNServer::init();
    state= ConfigModeState::Start;

    // Read mac address
    uint32_t addr0 = nrf_ficr_deviceaddr_get(NRF_FICR, 0);
    uint32_t addr1 = nrf_ficr_deviceaddr_get(NRF_FICR, 1);

    mac[0] = (addr0 >> 0) & 0xFF;
    mac[1] = (addr0 >> 8) & 0xFF;
    mac[2] = (addr0 >> 16) & 0xFF;
    mac[3] = (addr0 >> 24) & 0xFF;
    mac[4] = (addr1 >> 0) & 0xFF;
    mac[5] = (addr1 >> 8) & 0xFF;
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
                        /*if(this->config->getSsid()!= nullptr)
                            sprintf(resp, "$CONFIG,VAL,wssid,%s",this->config->getSsid());
                        else
                            sprintf(resp, "$CONFIG,VAL,wssid,");*/
                        sprintf(resp, "$CONFIG,VAL,wssid,");
                    } else if(parts[2]=="pcklk"){
                        /*if(this->config->getPicklock()!= nullptr)
                            sprintf(resp, "$CONFIG,VAL,pcklk,%s",this->config->getPicklock());
                        else
                            sprintf(resp, "$CONFIG,VAL,pcklk,");*/
                        sprintf(resp, "$CONFIG,VAL,pcklk,");
                    } else if(parts[2]=="tzone"){
                        /*if(this->config->getTimezone()!= nullptr)
                            sprintf(resp, "$CONFIG,VAL,tzone,%s",this->config->getTimezone());
                        else
                            sprintf(resp, "$CONFIG,VAL,tzone,");*/
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