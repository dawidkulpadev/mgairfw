//
// Created by dkulpa on 20.08.2025.
//

#ifndef MGLIGHTFW_G2_CONNECTIVITY_H
#define MGLIGHTFW_G2_CONNECTIVITY_H

#include "BLELN/BLELNClient.h"
#include "BLELN/BLELNServer.h"
#include "config.h"
#include "SuperString.h"

#define RECENTLY_HAS_BEEN_SERVER_PREFS_TAG  "rhbs"

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
