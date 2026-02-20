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

#ifndef MGLIGHTFW_CONNECTIVITYCLIENT_H
#define MGLIGHTFW_CONNECTIVITYCLIENT_H

#include "zephyr/kernel.h"
#include "bleln/BLELNClient.h"
#include "string"
#include "config.h"
#include "SuperString.h"

class ConnectivityClient {
public:
    typedef std::function<void(int requestId, int errorCode, int httpRespCode, const std::string &body)> OnApiResponseCb;

    static void init(ConnectivityClient::OnApiResponseCb onApiResponse);
    static void start();
    static void stop();

    static void startServerSearch(uint32_t maxDurationMs);
    static bool isConnected();

    enum class State {Init, Idle, ServerSearching, ServerChecking, ServerConnecting, ServerConnected,
        ServerNotFound, ServerConnectFailed, WaitingForHTTPResponse, HTTPResponseReceived, WiFiChecking, WiFiConnected, WiFiConnectFailed};
    enum class ConnectedFor {None, APITalk, TimeSync, Update};

    void loop();

    static void startAPITalk(const std::string& apiPoint, char method, const std::string& data); // Talk with API about me
private:
    explicit ConnectivityClient(ConnectivityClient::OnApiResponseCb onApiResponse);


    // Callbacks
    ConnectivityClient::OnApiResponseCb oar; // On API Response callback

    std::vector<std::string> serversBlacklist;

    bt_addr_le_t connectingWith;

    void onServerResponse(const std::string &msg);
    bool onServerFound(const bt_addr_le_t* addr);
    void onServerConnectResult(bool success, int err, uint8_t *macBE);
    void onServerDisconnect(int reason, const std::string& mac);


    bool runWorker;
    struct k_thread workerThread{};
};


#endif //MGLIGHTFW_CONNECTIVITYCLIENT_H
