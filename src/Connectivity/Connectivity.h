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

#ifndef MGLIGHTFW_G2_CONNECTIVITY_H
#define MGLIGHTFW_G2_CONNECTIVITY_H

#include "bleln/BLELNClient.h"
#include "bleln/BLELNServer.h"
#include "config.h"
#include "SuperString.h"

class ConnectivityClient;
class ConnectivityConfig;

class Connectivity {
public:
    enum class ConnectivityMode {ClientMode, ConfigMode};
    typedef std::function<void(int, int, int, const std::string &)> OnApiResponseCb;
    typedef std::function<void(ConnectivityMode)> RequestModeChangeCb;

    void start(uint8_t devMode, const OnApiResponseCb &onApiResponse);
    void loop();

private:
    ConnectivityClient *conClient= nullptr;
    ConnectivityConfig *conConfig= nullptr;

    ConnectivityMode conMode= ConnectivityMode::ClientMode;
};

#endif //MGLIGHTFW_G2_CONNECTIVITY_H
