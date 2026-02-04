//
// Created by dkulpa on 30.09.2025.
//

#ifndef MGLIGHTFW_CONNECTIVITYCLIENT_H
#define MGLIGHTFW_CONNECTIVITYCLIENT_H

#include "zephyr/kernel.h"
#include "BLELN/BLELNClient.h"
#include "string"
#include "config.h"
#include "SuperString.h"
#include "Connectivity.h"

#define CLIENT_SERVER_CHECK_INTERVAL        ((5*60)*1000ul)       // 5 min
#define CLIENT_TIME_SYNC_INTERVAL           ((600)*1000ul)        // 10 min
#define WIFI_NTP_MAX_RETIRES                1
#define BLE_REASON_MAX_CLIENTS              1 // TODO: Replace with real value

class ConnectivityClient {
public:
    ConnectivityClient(Connectivity::OnApiResponseCb onApiResponse,
                       Connectivity::RequestModeChangeCb requestModeChange);

    enum class State {Init, Idle, ServerSearching, ServerChecking, ServerConnecting, ServerConnected,
        ServerNotFound, ServerConnectFailed, WaitingForHTTPResponse, HTTPResponseReceived, WiFiChecking, WiFiConnected, WiFiConnectFailed};
    enum class ConnectedFor {None, APITalk, TimeSync, Update};


    void loop();
    void startAPITalk(const std::string& apiPoint, char method, const std::string& data); // Talk with API about me
private:

    State state;                            // State in client mode
    BLELNClient blelnClient;

    // Callbacks
    Connectivity::OnApiResponseCb oar; // On API Response callback
    Connectivity::RequestModeChangeCb rmc;

    void onServerResponse(const std::string &msg);
    void finish();
    void switchToServer();
    // Client mode variables
    unsigned long lastServerCheck=0;
    unsigned long lastTimeSync=0;
    ConnectedFor connectedFor;

    // My API Talk variables
    bool meApiTalkRequested= false;
    std::string meApiTalkData;
    std::string meApiTalkPoint;
    char meApiTalkMethod='N';

    bool firstServerCheckMade= false;
};


#endif //MGLIGHTFW_CONNECTIVITYCLIENT_H
