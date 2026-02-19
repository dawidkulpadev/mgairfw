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

#ifndef MGLIGHTFW_CONNECTIVITYCONFIG_H
#define MGLIGHTFW_CONNECTIVITYCONFIG_H

#include "bleln/BLELNServer.h"
#include "SuperString.h"
#include <nrfx.h>
#include <hal/nrf_ficr.h>
#include "config.h"
#include <zephyr/sys/reboot.h>
#include <zephyr/kernel.h>

class ConnectivityConfig {
public:
    static void init();
    static void start();
    static void stop();

    void loop();
    uint8_t* getMAC();
private:
    explicit ConnectivityConfig();

    bool runWorker;
    struct k_thread workerThread{};

    uint8_t mac[6]{};
    bool rebootCalled = false;                          // Reboot called by configuration app
    int64_t rebootCalledAt= ULONG_MAX - 10000;    // When reboot was called
};


#endif //MGLIGHTFW_CONNECTIVITYCONFIG_H
