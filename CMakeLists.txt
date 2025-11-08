# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(mgairfw C CXX)

target_sources(app PRIVATE src/main.cpp src/BLELN/BLELNBase.cpp src/BLELN/BLELNBase.h src/BLELN/BLELNClient.h
        src/BLELN/BLELNClient.cpp src/BLELN/BLELNConnCtx.h src/BLELN/BLELNConnCtx.cpp
        src/BLELN/BLELNEncryptData.h src/BLELN/BLELNEncryptData.cpp
        src/BLELN/BLELNMessage.cpp src/BLELN/BLELNMessage.h
        src/BLELN/BLELNServer.h src/BLELN/BLELNServer.cpp)
