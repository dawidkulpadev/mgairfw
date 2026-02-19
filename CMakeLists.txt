cmake_minimum_required(VERSION 3.20.0)

list(APPEND BOARD_ROOT ${CMAKE_CURRENT_SOURCE_DIR})

find_package(Zephyr)
project(mgairfw)

include_directories(src)
target_sources(app PRIVATE src/main.cpp src/bleln/BLELNBase.cpp src/bleln/BLELNBase.h src/bleln/BLELNClient.h
        src/bleln/BLELNClient.cpp src/bleln/BLELNConnCtx.cpp src/bleln/BLELNConnCtx.h
        src/bleln/BLELNServer.cpp src/bleln/BLELNServer.h
        src/Connectivity/ConnectivityConfig.h src/Connectivity/ConnectivityConfig.cpp
        src/Connectivity/ConnectivityClient.h src/Connectivity/ConnectivityClient.cpp
        src/SuperString.h src/SuperString.cpp src/bleln/BLELNAuthentication.h src/bleln/BLELNAuthentication.cpp
        src/bleln/Encryption.cpp src/bleln/Encryption.h src/bleln/BLELNCert.cpp src/bleln/BLELNCert.h
        src/bleln/BLELNSessionEnc.cpp src/bleln/BLELNSessionEnc.h src/DeviceConfig.h src/DeviceConfig.cpp src/Sht45Sensor.h
        src/Sht45Sensor.cpp)
