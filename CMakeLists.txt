cmake_minimum_required(VERSION 3.20.0)

list(APPEND BOARD_ROOT ${CMAKE_CURRENT_SOURCE_DIR})

find_package(Zephyr)
project(mgairfw)

include_directories(src)
target_sources(app PRIVATE src/main.cpp src/BLELN/BLELNBase.cpp src/BLELN/BLELNBase.h src/BLELN/BLELNClient.h
        src/BLELN/BLELNClient.cpp src/BLELN/BLELNConnCtx.cpp src/BLELN/BLELNConnCtx.h
        src/BLELN/BLELNServer.cpp src/BLELN/BLELNServer.h
        src/Connectivity/Connectivity.h src/Connectivity/Connectivity.cpp
        src/Connectivity/ConnectivityConfig.h src/Connectivity/ConnectivityConfig.cpp
        src/Connectivity/ConnectivityClient.h src/Connectivity/ConnectivityClient.cpp
        src/SuperString.h src/SuperString.cpp src/BLELN/BLELNAuthentication.h src/BLELN/BLELNAuthentication.cpp
        src/BLELN/Encryption.cpp src/BLELN/Encryption.h src/BLELN/BLELNCert.cpp src/BLELN/BLELNCert.h
        src/BLELN/BLELNSessionEnc.cpp src/BLELN/BLELNSessionEnc.h)
