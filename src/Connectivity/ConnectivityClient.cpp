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

#include "ConnectivityClient.h"
#include "DeviceConfig.h"
#include <utility>

K_THREAD_STACK_DEFINE(g_connectivityclient_worker_stack, 1024)

static ConnectivityClient *instance;

void ConnectivityClient::init(ConnectivityClient::OnApiResponseCb onApiResponse) {
    instance= new ConnectivityClient(onApiResponse);
}

void ConnectivityClient::start() {
    if(!instance) return;

    BLELNClient::setOnDisconnectCallback([](int reason, uint8_t* mac){
        instance->onServerDisconnect(reason, "");
    });
    BLELNClient::start(BLE_NAME, [](const std::string& msg){
        instance->onServerResponse(msg);
    });


    instance->runWorker= true;
    k_thread_create(&instance->workerThread, g_connectivityclient_worker_stack, K_THREAD_STACK_SIZEOF(g_connectivityclient_worker_stack),
                    [](void* p1, void*, void*) {
                        while(instance->runWorker){
                            instance->loop();
                        }
                    }, nullptr, nullptr, nullptr, K_PRIO_COOP(8), 0, K_NO_WAIT);
}

void ConnectivityClient::stop() {
    instance->runWorker= false;
    BLELNClient::stop();

    if(k_thread_join(&instance->workerThread, K_MSEC(1000))){
        k_thread_abort(&instance->workerThread);
    }
}

bool ConnectivityClient::isConnected() {
    return instance and BLELNClient::isConnected();
}


ConnectivityClient::ConnectivityClient(ConnectivityClient::OnApiResponseCb onApiResponse) {
    BLELNClient::init(devicesConfig.getCertSign(), devicesConfig.getManuPubKey(),
                      devicesConfig.getMyPrivateKey(), devicesConfig.getMyPublicKey(),
                      devicesConfig.getUid());

    oar= std::move(onApiResponse);
    runWorker= false;
}


void ConnectivityClient::loop() {
    k_sleep(K_MSEC(200));
}


void ConnectivityClient::onServerResponse(const std::string &msg) {
    StringList parts= splitCsvRespectingQuotes(msg);
    if(parts[0]=="$ATRS" and parts.size()==5){
        int rid= strtol(parts[1].c_str(), nullptr, 10);
        int errc= strtol(parts[2].c_str(), nullptr, 10);
        int httpCode= strtol(parts[3].c_str(), nullptr, 10);
        if(rid!=0){
            if(oar)
                oar(rid, errc, httpCode, parts[4]);
        }
    }
}


void ConnectivityClient::startAPITalk(const std::string& apiPoint, char method, const std::string& data) {
    char buf[200];
    sprintf(buf, "$ATRQ,1,%s,%c,%s,%s,%s",apiPoint.c_str(),method,DeviceConfig::getMyMAC().c_str(),
            devicesConfig.getPicklock().c_str(),data.c_str());

    BLELNClient::sendEncrypted(buf);
}

void ConnectivityClient::startServerSearch(uint32_t maxDurationMs) {
    BLELNClient::startServerSearch(maxDurationMs, BLELN_HTTP_REQUESTER_UUID,
                                   [](const bt_addr_le_t* addr) -> bool{
        return instance->onServerFound(addr);
    });
}

bool ConnectivityClient::onServerFound(const bt_addr_le_t *addr) {
    if(devicesConfig.getLastServerMAC().empty()){
        // Search for my users server
        if(std::find(serversBlacklist.begin(), serversBlacklist.end(), BLELNClient::addrToRawHex(addr))!= serversBlacklist.end()){
            printk("[D] ConnectivityClient - Black list - MAC in black list\n");
            return false; // Continue scanning
        } else {
            printk("[D] ConnectivityClient - Black list - begin connect\n");
            connectingWith= *addr;
            BLELNClient::beginConnect(addr, [this](bool r, int e, uint8_t *macBE){
                this->onServerConnectResult(r, e, macBE);
            });
            return true;
        }
    } else {
        // Try to connect with white server
        if(BLELNClient::addrToRawHex(addr)==devicesConfig.getLastServerMAC()){
            printk("[D] ConnectivityClient - White list - begin connect\n");
            connectingWith= *addr;
            BLELNClient::beginConnect(addr, [this](bool r, int e, uint8_t *macBE){
                this->onServerConnectResult(r, e, macBE);
            });
            return true;
        } else {
            printk("[D] ConnectivityClient - White list - not white MAC\n");
            return false; // Continue scanning
        }
    }

    return false;
}



void ConnectivityClient::onServerConnectResult(bool success, int err, uint8_t *macBE) {
    printk("[D] ConnectivityClient - connect result: %d, %d\n", success, err);
    if(success){

    } else {
        if(err <= -100){
            err+=100;

            if(err==-BT_HCI_ERR_CONN_FAIL_TO_ESTAB){
                printk("asd1\n");
                BLELNClient::beginConnect(&connectingWith, [this](bool r, int e, uint8_t *macBE){
                    this->onServerConnectResult(r, e, macBE);
                });
            } else {
                printk("asd2\n");
            }
        } else {
            if (macBE) {
                char b[16];
                sprintf(b, "%02X%02X%02X%02X%02X%02X", macBE[0], macBE[1], macBE[2], macBE[3], macBE[4], macBE[5]);
                serversBlacklist.emplace_back(b);
            }
            printk("[D] ConnectivityClient - Failed connecting! Next scan started!\n");
            startServerSearch(20000);
        }
    }
}

void ConnectivityClient::onServerDisconnect(int reason, const std::string &mac) {

}





