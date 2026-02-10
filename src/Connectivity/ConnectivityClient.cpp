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

#include <utility>

ConnectivityClient::ConnectivityClient(Connectivity::OnApiResponseCb onApiResponse,
                                       Connectivity::RequestModeChangeCb requestModeChange) {
    oar= std::move(onApiResponse);
    rmc= std::move(requestModeChange);
    state= State::Init;
    connectedFor= ConnectedFor::None;
    meApiTalkRequested= false;
}


void ConnectivityClient::loop() {

}


void ConnectivityClient::onServerResponse(const std::string &msg) {

}


void ConnectivityClient::finish() {

}

void ConnectivityClient::switchToServer() {
}


void ConnectivityClient::startAPITalk(const std::string& apiPoint, char method, const std::string& data) {

}
