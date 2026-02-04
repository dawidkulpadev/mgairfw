//
// Created by dkulpa on 1.10.2025.
//

#ifndef MGLIGHTFW_CONNECTIVITYCONFIG_H
#define MGLIGHTFW_CONNECTIVITYCONFIG_H

#include "BLELN/BLELNServer.h"
#include "SuperString.h"
#include <nrfx.h>
#include <hal/nrf_ficr.h>
#include "config.h"
#include <zephyr/sys/reboot.h>

class ConnectivityConfig {
public:
    enum class ConfigModeState {Start, ServerTasking};

    explicit ConnectivityConfig();//, Preferences *preferences, DeviceConfig* deviceConfig);
    void loop();
    uint8_t* getMAC();
private:

    ConfigModeState state;                           // State in config mode

    uint8_t mac[6]{};
    bool rebootCalled = false;                          // Reboot called by configuration app
    int64_t rebootCalledAt= ULONG_MAX - 10000;    // When reboot was called
};


#endif //MGLIGHTFW_CONNECTIVITYCONFIG_H
