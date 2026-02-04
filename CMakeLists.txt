cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr)
project(mgairfw)

include_directories(src)
target_sources(app PRIVATE src/main.cpp src/BLELN/BLELNBase.cpp src/BLELN/BLELNBase.h src/BLELN/BLELNClient.h
        src/BLELN/BLELNClient.cpp src/BLELN/BLELNConnCtx.cpp src/BLELN/BLELNConnCtx.h
        src/BLELN/BLELNEncryptData.cpp src/BLELN/BLELNEncryptData.h
        src/BLELN/BLELNServer.cpp src/BLELN/BLELNServer.h
        src/Connectivity/Connectivity.h src/Connectivity/Connectivity.cpp
        src/Connectivity/ConnectivityConfig.h src/Connectivity/ConnectivityConfig.cpp
        src/Connectivity/ConnectivityClient.h src/Connectivity/ConnectivityClient.cpp
        src/SuperString.h src/SuperString.cpp)
