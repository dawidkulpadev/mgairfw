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

#include "BLELNBase.h"

void hexDump(const char* label, const uint8_t* data, size_t len) {
    printk("%s [%u]: ", label, (unsigned)len);
    for (size_t i = 0; i < len; ++i) {
        printk("%02X", data[i]);
        if (i + 1 < len) printk(" ");
        if (i != 0 && (i % 20) == 0) printk("\r\n");
    }
    printk("\r\n");
}