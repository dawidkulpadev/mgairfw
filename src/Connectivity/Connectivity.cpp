//
// Created by dkulpa on 20.08.2025.
//

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

/**
 * Nie dzielić danych na normalne i abnormal jako dwie klasy tylko każdy wynik jest wektorem pokazującym miejsce w prestrzeni
 * i teraz podejście pierwsze to np zrobic że dane normalne mają pozycje blisko siebie a abnormalne nie ważne gdzie są ale ważne że
 * ich odległość od zbioru normalnego jest "duża"
 *
 * Autoenkoder - ważna rzecz
 */

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







