//
// Created by dkulpa on 30.09.2025.
//

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
