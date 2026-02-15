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
#include <vector>
#include "Connectivity.h"
#include "ConnectivityClient.h"
#include "ConnectivityConfig.h"

void Connectivity::start(uint8_t devMode, const OnApiResponseCb &onApiResponse) {

    if(devMode==DEVICE_MODE_CONFIG) {
        printk("Start config mode\r\n");
        conConfig= new ConnectivityConfig();
        conMode = ConnectivityMode::ConfigMode;
    } else {
        printk("Start client mode\r\n");
        conClient= new ConnectivityClient(onApiResponse,
                                          [this](ConnectivityMode m){
            this->conMode= m;
        });
        conMode = ConnectivityMode::ClientMode;
    }
}


void Connectivity::loop() {
    switch(conMode){
        case ConnectivityMode::ClientMode:
            if(conClient!= nullptr)
                conClient->loop();
            break;
        case ConnectivityMode::ConfigMode:
            if(conConfig!= nullptr)
                conConfig->loop();
            break;
    }

    k_sleep(K_MSEC(10));
}







